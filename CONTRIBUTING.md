# Contributing to Drydock

Issues and pull requests are welcome. Keep changes small, add a focused test
for changed behaviour, and do not include credentials, customer archives, or
generated secrets in a contribution.

## Licensing of contributions: sign your commits

Drydock is [AGPL-3.0](LICENSE), and contributions are accepted under that same
licence — inbound matches outbound. There is no copyright assignment and no
contributor licence agreement to sign, which also means the project cannot
relicense your work or offer it under a commercial licence without asking you.
That is a deliberate trade: no paperwork stands between you and a first pull
request, and in exchange the licence is settled for good.

What is asked instead is a sign-off. Add `-s` when you commit:

```bash
git commit -s -m "Fix the thing"
```

That appends one line to the message:

```
Signed-off-by: Your Name <your.email@example.com>
```

By adding it you certify the Developer Certificate of Origin below — in plain
terms, that you wrote the patch or otherwise have the right to submit it under
AGPL-3.0. It is a statement about provenance, not a transfer of rights: you
keep the copyright in your work.

Use a real name and a real address; `--signoff` uses your git identity, so set
`user.name` and `user.email` first if they are not already right. If you forget
on the last commit, `git commit --amend -s` fixes it.

## Developer Certificate of Origin 1.1

```
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

The full text is at <https://developercertificate.org/>.

## Running a modified copy

AGPL-3.0 section 13 applies to network use: if you deploy a modified Drydock
where other people can reach it, you owe those users the corresponding source
of the version you are running. See the README's licence section for how the
hosted service at drydock.co meets that, including the `source` field of
`GET /version`, which names the exact tree that answered the request.
