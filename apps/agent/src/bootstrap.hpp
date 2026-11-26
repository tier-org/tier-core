#pragma once

namespace tier::agent {

// argc/argv begin at the role, after "tier-agent bootstrap".
int run_bootstrap(int argc, char* const argv[]);

}  // namespace tier::agent
