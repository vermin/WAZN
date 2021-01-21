# Contributing to WAZN

## General guidelines

* Comments are encouraged.
* If modifying code for which Doxygen headers exist, that header must be modified to match.
* Tests would be nice to have if you're adding functionality.
* Patches are to be sent via a Github pull request.

Patches should be self contained. A good rule of thumb is to have
one patch per separate issue, feature, or logical change. Also, no
other changes, such as random whitespace changes, reindentation,
or fixing typoes, spelling, or wording, unless user visible.
Following the code style of the particular chunk of code you're
modifying is encouraged. Proper squashing should be done (eg, if
you're making a buggy patch, then a later patch to fix the bug,
both patches should be merged).

If you've made random unrelated changes (either because your editor
is annoying or you made them for other reasons), you can select
what changes go into the coming commit using git add -p, which
walks you through all the changes and asks whether or not to
include this particular change. This helps create clean patches
without any irrelevant changes. git diff will show you the changes
in your tree. git diff --cached will show what is currently staged
for commit. As you add hunks with git add -p, those hunks will
"move" from the git diff output to the git diff --cached output,
so you can see clearly what your commit is going to look like.

## License

Copyright (c) 2017-2018 The Monero Project
Copyright (c) 2019-2021 WAZN Project
