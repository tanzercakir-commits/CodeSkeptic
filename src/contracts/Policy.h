#ifndef CODESKEPTIC_CONTRACT_POLICY_H
#define CODESKEPTIC_CONTRACT_POLICY_H

// Policies (CONTRACTS.md §2.3, Round E): AST-level pattern
// prohibitions under the shared cs: surface — a different
// verification engine from the dataflow contracts. v1 ships ONE
// policy, no-absolute-paths: the founding Ruledsl incident (a
// hard-coded config path shipped in a release) immortalized as the
// first machine-checked rule.
//
// Activation: `// cs:policy <name>` anywhere in a file scopes the
// policy to THAT file; project-wide activation comes from the idiom
// profile (`policy = <name>` in .codeskeptic.conf or --policy). An
// unknown policy name is a contract-syntax error — never silently
// inert.

#include <set>
#include <string>

namespace codeskeptic {

bool isKnownPolicy(const std::string& name);

// Profile-level (project-wide) policies from config.
void setProfilePolicies(const std::set<std::string>& names);
const std::set<std::string>& profilePolicies();

// no-absolute-paths: does this string literal look like a hard-coded
// absolute filesystem path? Deliberately conservative — at least two
// path segments (`/etc/app.conf` yes, a lone `/` or `/tmp` no), no
// whitespace (prose containing slashes is not a path), or a Windows
// drive root (`C:\...`). Exposed for unit tests.
bool looksLikeAbsolutePath(const std::string& text);

} // namespace codeskeptic

#endif // CODESKEPTIC_CONTRACT_POLICY_H
