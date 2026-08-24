# Contributing

## Getting Started

We're happy to accept external contributions.  Before working on
something, however, please coordinate with us to make sure that we're
interested in the change and are not already working on it, and that
we agree on the shape of the solution.

There are two main ways to contact us.  You can start a discussion on
our [irc channel](https://webchat.oftc.net/?channels=#sequoia)
(there is also a Matrix bridge), or you can open an issue or comment on
an existing one.

## Commits

A commit should consist of a single change with no known regressions.

Each commit should encompass a single, minimal change.  For instance,
when working on a new feature, it is often helpful to refactor some
code.  Each refactoring should be in its own commit.  This simplifies
reviewing changes.  Sometimes multiple changes are tightly coupled.
In that case, it is okay to have a single commit for those changes.
Make sure that the commit message discusses all of the changes, and
mentions why they can't be broken up.

Often a larger change consists of multiple commits.  When adding a new
feature, you'll often have several commits that refactor some code
before the commit that implements the actual feature.  Security issues
are handled differently.  When fixing a security issue, the security
issue must be fixed by the first commit.  Commits that do any
refactoring must follow.  This may complicate the fix, but it
simplifies back porting the security fix.

Each commit must compile and pass the test suite.  When fixing an
issue, some projects merge one commit that adds a unit test that
demonstrates the problem, followed by another commit that fixes the
issue and the unit test.  We don't do that.  Having each commit
compile and pass the test suite makes it easier to use `git bisect` to
identify where some behavior changed.

## Churn

Commits that only add churn should be avoided.

A commit should fix a bug, add a new feature, or refactor code.
Please do not submit commits that only reformat code or fix a lint
that doesn't have a demonstrably impact on security or performance.

The main reason for this has to do with simplifying the handling of
security fixes.  When we patch a security vulnerability, we (or a
downstream) may back port it to an earlier version.  Small changes in
the code may make a change that would otherwise apply cleanly result
in a merge conflict, which needs to be resolved by hand.  Dealing with
security vulnerabilities is already stressful.  Having to also deal
with a merge conflict adds additional stress, which can result in
mistakes.

## Formatting

We don't currently use `rustfmt`.

There are several reasons for this.  In the past, `rustfmt` changed
Sequoia's code in such a way that it didn't compile.  See these
issues for a discussion:

  - https://gitlab.com/sequoia-pgp/sequoia/-/work_items/756
  - https://github.com/rust-lang/rustfmt/issues/4996
  - https://gitlab.com/sequoia-pgp/sequoia/-/merge_requests/1145

This raises a potential security concern: could `rustfmt` (maliciously
or not) change code such that it introduces a security issue?  The
answer is clearly yes.  This means that to help mitigate the issue, we
need to review changes made by `rustfmt`, which is a burden.

Given that we haven't used `rustfmt`, switching to it now would also
mean a lot of churn.  Further, it would introduce churn whenever
`rustfmt` adds new formatting rules.  It is possible to tell `git
blame` to ignore those commits using `--ignore-rev-file` (or git's
`blame.ignoreRevsFile` configuration key), which is helpful when using
`git blame` to navigate a project's history, but that does not address
the more important issue of applying security fixes to older versions
(see the section on Churn).  It also doesn't help with porting patches
across a reformatting, or keeping copies of code across projects in
sync, in particular, when a three-way merge is required because both
copies have changed.  See also:

  - https://gitlab.com/sequoia-pgp/sequoia-sq/-/work_items/124

Another issue with a formatter is that it applies a global formatting
policy, which can sometimes reduce readability.  For instance, imagine
we use white space to organize data in a tabular form to facilitate
scanning, [like
this](https://gitlab.com/sequoia-pgp/sequoia/-/blob/2a19b792/openpgp/src/crypto/hash.rs#L653-656):

```rust
buffer[1] = (creation_time >> 24) as u8;
buffer[2] = (creation_time >> 16) as u8;
buffer[3] = (creation_time >>  8) as u8;
buffer[4] = (creation_time      ) as u8;
```

`rustfmt` would break the tabular format.  This is one example, and it
is not hard to come up with a solution that works around this
individual case.  But there are others.

### Formatting Guidelines

Given the above here are a few guidelines.  Note: as you read the
code, you'll see that these guidelines are not always followed.  Some
of these guidelines have changed with time, and sometimes we weren't
careful enough.  We could fix these issues, but it would just
introduce churn, which we want to avoid.

  - Please break lines between 72 and 80 characters unless there are local
    reasons why not breaking would make the code more readable.

  - Sort `use` statements so that the most general-purpose, low-level
    `crates` come first.

    Yes:

    ```
    use std::...

    use anyhow::...

    use sequoia_openpgp::...

    use crate::...
    ```

  - When importing an item, please import one item per line.

    Yes:

    ```
    use std::io::Read;
    use std::io::Write;
    ```

    No:

    ```
    use std::io::{Read, Write};
    ```

  - When documenting something, please put the comment above the field
    or variant and not at the end of the line.

    Yes:

    ```
    struct Foo {
        // A comment.
        field: Type,
    }
    ```

    No:

    ```
    struct Foo {
        field: Type, // A comment.
    }
    ```

  - As `std` is a superset of `core` and we don't support non-`std`
    builds, please use `std` instead of `core` to include standard
    library functionality.

  - After keywords, `,` and `:` please put a space.

    Yes:

    ```
    fn foo(parameter: Type)
    ```

    No:

    ```
    fn foo(parameter:Type)
    ```

If you're uncertain, don't worry: we'll clean it up before merging
your change.

## Tests

Commits that fix bugs or add new features should include unit tests
that demonstrate the issue, or exercise the new functionality.

We primarily rely on Rust's built-in unit and integration test
framework.  Although we may consider other test frameworks, we are
conservative about adding new test frameworks.  Rewriting tests is a
huge amount of work, easy to get wrong (does the test check the same
thing?), and not particularly fun.  In other words, moving from one
test framework to another requires a lot of effort, and is better
avoided.  And since we want to minimize our dependencies, we want to
minimize the number of test frameworks.

## Documentation

New functionality should be well documented.  Ideally, new APIs should
include examples.

## News

New functionality and non-trivial bug fixes should be mentioned in the
project's `NEWS` file.  See
[https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/openpgp/NEWS]
for an example.

## Merge Requests

We use a linear history.  That is, we don't use merge commits.  If
necessary, changes are rebased.

## Continuous Integration

If you make a merge request from a fork of a project, the CI will
fail.  This is because we have our own CI infrastructure and we don't
want randos to abuse our infrastructure by creating merge requests
that either waste our resources, or use our infrastructure to launch
an attack.  After someone reviews an MR from a fork, they will push
the changes to a branch in our name space, which will run the CI
pipeline.

## Commit Signing

We sign all commits, and tags.  The signatures must be made by OpenPGP
certificates that are permitted according to the project's signing
policy.  Signatures are automatically checked by the
`authenticate-commits` CI job.  If you are not a regular contributor,
you don't have to worry about signing your commits: whoever reviews
your contribution will sign the commits before merging them into the
`main` branch.

Because all commits must be signed, the forge cannot be used to
rewrite merge requests.  In particular, `gitlab`'s rebase
functionality cannot be used as it modifies the commits, which strips
the signatures, because the rebase operation invalidates them.  This
means that to rebase whoever merges the MR pulls the changes, rebases
locally, and then pushes.  This is less convenient, but has the
advantage that the forge (or an attacker who has compromised the
forge) cannot modify the repository without detection.

We use [`sq-git`](https://gitlab.com/sequoia-pgp/sequoia-git) to
manage and enforce the signing policy.  Each repository contains an
`openpgp-policy.toml` file (like [this
one](https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/openpgp-policy.toml?ref_type=heads))
that contains a list of certificates that are allowed to make
different types of changes to the repository.  `sq-git policy
describe` displays the policy is a more human-readable format.

If a certificate expires, anyone who is allowed to commit to the
repository can update it (even if it is their own certificate that is
expired).  You can update certificates using `sq-git policy sync`,
which looks for certificate updates in your local certificate store as
well as on popular key servers.

## Developer Certificate of Origin

Sequoia PGP is licensed under the terms of the LGPL-2.0-or-later.

Contributions are governed by the Developer Certificate of Origin,
which can be obtained from [https://developercertificate.org/].  A
copy is reproduced below, for your convenience.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
