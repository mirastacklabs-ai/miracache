// SPDX-License-Identifier: Apache-2.0
// Store one block in the memory nodes, look it up, fetch it back and compare, using the C++ client.
//
//   example_cpp_put_fetch /path/to/client.toml
//
// The client config names the memory nodes and the deployment secret file (see deploy/examples/client.toml).
// The data path never throws: every operation returns a Ticket, and the Completion that follows carries one
// KeyStatus per key. The caller's buffers must stay valid until that completion arrives.
#include <poll.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "miracache/config.h"
#include "miracache/scope.h"
#include "scope/engine_native.h"
#include "src/client.h"

using namespace miracache;

namespace {

// Waits for the completion of `t` (submits are non-blocking; completions arrive through poll()).
bool wait_for(Client& cl, Ticket t, Completion& out) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (std::chrono::steady_clock::now() < deadline) {
    pollfd pfd{cl.eventfd(), POLLIN, 0};  // readable whenever completions are pending
    ::poll(&pfd, 1, 200);
    std::array<Completion, 8> done;
    const std::size_t n = cl.poll(done);
    for (std::size_t i = 0; i < n; ++i)
      if (done[i].ticket == t) {
        out = std::move(done[i]);
        return true;
      }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s client.toml\n", argv[0]);
    return 2;
  }

  // 1. Load the configuration and the deployment secret, then connect to the memory nodes.
  auto cfg = load_config(argv[1]);
  if (!cfg) {
    std::fprintf(stderr, "config: %s\n", to_string(cfg.error().code));
    return 1;
  }
  auto provider = ReloadableEngineNativeProvider::from_file(cfg->secret_file);
  if (!provider) {
    std::fprintf(stderr, "secret file: %s\n", to_string(provider.error().code));
    return 1;
  }
  auto opened = Client::open(*cfg, **provider);  // the provider must outlive the client
  if (!opened) {
    std::fprintf(stderr, "open: %s\n", to_string(opened.error().code));
    return 1;
  }
  Client& cl = **opened;

  // 2. Derive the scope: who may read this block. An engine passes its namespace digest (32 bytes) and the
  // raw key of each KV-cache group's chain root; here one group with a fixed example namespace.
  RequestMeta meta;
  meta.engine = EngineKind::Vllm;
  for (std::size_t i = 0; i < meta.ns.size(); ++i) meta.ns[i] = static_cast<std::uint8_t>(i);
  const std::string root = "example-root";
  meta.roots.push_back(std::vector<std::byte>(reinterpret_cast<const std::byte*>(root.data()),
                                              reinterpret_cast<const std::byte*>(root.data()) + root.size()));
  auto scope = (*provider)->derive(meta);
  if (!scope) {
    std::fprintf(stderr, "derive: %s\n", to_string(scope.error().code));
    return 1;
  }

  // 3. One block: a raw key (the engine's block hash) and 64 KiB of data.
  const std::string raw = "example-block-0";
  KeyRef key;
  key.raw = {reinterpret_cast<const std::byte*>(raw.data()), raw.size()};  // no parent: a chain root
  std::vector<std::byte> src(64 * 1024), dst(64 * 1024);
  for (std::size_t i = 0; i < src.size(); ++i) src[i] = static_cast<std::byte>((i * 31 + 5) & 0xFF);
  const std::array<KeyRef, 1> keys{key};
  const Nanos timeout = std::chrono::seconds(10);
  Completion c;

  // 4. Store, then look up, then fetch into dst. Group 0 is the first (here: only) root.
  const std::array<BufRef, 1> put_buf{BufRef{std::span<std::byte>(src)}};
  if (!wait_for(cl, cl.store(*scope, 0, keys, put_buf, timeout), c) || c.status.size() != 1 ||
      c.status[0] != KeyStatus::Committed) {
    std::fprintf(stderr, "store failed\n");
    return 1;
  }
  std::printf("store:  %s\n", to_string(c.status[0]));

  if (!wait_for(cl, cl.lookup(*scope, 0, keys, timeout), c) || c.status.size() != 1 || c.status[0] != KeyStatus::Hit) {
    std::fprintf(stderr, "lookup did not hit\n");
    return 1;
  }
  std::printf("lookup: %s\n", to_string(c.status[0]));

  const std::array<BufRef, 1> get_buf{BufRef{std::span<std::byte>(dst)}};
  if (!wait_for(cl, cl.fetch(*scope, 0, keys, get_buf, timeout), c) || c.status.size() != 1 ||
      c.status[0] != KeyStatus::Hit) {
    std::fprintf(stderr, "fetch failed\n");
    return 1;
  }
  if (std::memcmp(src.data(), dst.data(), src.size()) != 0) {
    std::fprintf(stderr, "fetched bytes differ\n");
    return 1;
  }
  std::printf("fetch:  %s, %zu bytes identical\n", to_string(c.status[0]), dst.size());

  cl.shutdown();  // stops accepting work and drains; the destructor does it too
  std::printf("PASS\n");
  return 0;
}
