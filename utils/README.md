MPTCP Maintainers scripts
=========================

Here are a bunch of (often quickly made) scripts to help maintaining MPTCP in
the upstream Linux kernel.

TopGit is used to maintain MPTCP patches. The main reasons are:

* to list all MPTCP-related patches on top of `net` and `net-next`
* to insert only once patches that are for both `net` and `net-next`
* to be able to easily modify MPTCP-related patches not in `net` or `net-next`
  yet while still be able to track the modifications by not doing any `git rebase`
* to easily track issues when syncing with `net` and `net-next`
* because why not :)

The main drawbacks are:

* the `export` branches are overriden but:
  * same result as a `git rebase`
  * `for-review` branches are there to avoid devs to do `git rebase --onto`
* moving topics (exported commits) is a pain


An interim MPTCP maintainer doesn't need to know how TopGit works. The best is
to only use the scripts and that's it. In case of issues, `git status` or
`tg status` will tell you how to abord the current operation.


The most important operations are explained here below.


Setup the environment
---------------------

Clone only this branch in a dedicated directory:

    git clone -b scripts --single-branch https://github.com/multipath-tcp/mptcp_net-next.git scripts

From the root directory of the kernel repo, run:

    ../<path to "scripts" dir>/utils/setup.sh

This will create symlink with files starting with a `.`. (Note that it would
have been better to use something like `direnv` to clone the repo and set `PATH`
correctly but well, it is still possible to change all scripts...)

Some tools are needed:

    pip install b4

    pip install git-pw

    git clone https://github.com/mackyle/topgit.git
    cd topgit
    sudo make prefix=/usr install

You also need Patchwork write permission and setup
[git-pw](https://github.com/getpatchwork/git-pw#getting-started=).

(Re-) Init the TopGit tree
--------------------------

The first time but also *each time you want to manipulate the tree*, you should
sync with the remote using:

    ./.update.sh


Manual sync with `net` and `net-next`
-------------------------------------

If needed to avoid conflicts or to fix conflicts reported by the CI:

    ./.update.sh && ./.update.sh new

You can also prune the TopGit tree manually with `./.tg-remove-empty.sh`.


Fix conflicts resolved differently upstream
-------------------------------------------

It can happen the net maintainers resolve conflicts between -net and net-next
differently than what was proposed and applied in our tree.

No need to create a new dedicated topic for that or update
`t/DO-NOT-MERGE-git-markup-net-next`, the proper solution is to do the fix in
the associated top-base ref to align on what is done upstream:

    git switch --detach top-bases/t/DO-NOT-MERGE-git-markup-net-next
    <do the modifications>
    git add -p
    git commit -sm "..."
    git diff net-next -- <file> # just to check
    git update-ref refs/top-bases/t/DO-NOT-MERGE-git-markup-net-next HEAD
    ./.publish.sh

One way to check that our tree doesn't diverge with upstream is to look at:

    git diff t/DO-NOT-MERGE-git-markup-net-next t/DO-NOT-MERGE-git-markup-end-common-net-net-next net-next -- *


Add a new patch to the tree
---------------------------

`add_patch_*.sh` scripts can be used to add a patch in the tree, e.g.

    ./.add_patch_feat_net-next.sh [<Message-ID> | patch <Patchwork ID> | series <Patchwork ID> | mbox file]

This will add the patch(es) in "Features for net-next" section, update the tree,
rewrite the `export` and `for-review` branches (+tags) and publish to the
`origin` remote.

The different sections in the TopGit tree:

* Fixes for others: not specific to `net`, issues in Linus tree
* Fixes for net: for `net` and `net-next`
* Fixes for net-next: only for `net-next`
* Features for others: to be send to another ML than `netdev`
* Features for net-next: not including BPF for the moment
* Features for net-next next: when a long series is in developments or for BPF

All these scripts call `add_patch.sh` after having set `TG_TOP`. You can do the
same if you need to place a patch before a specific topic (Git branch) or use
`add_patch_before_commit.sh "<commit title>" (...)`. Check the `Find a topic
name` section below.

In case of conflicts, please follow the intructions and use `./.end-conflict.sh`.


Amend of topic (Apply a `Squash-to` patch)
------------------------------------------

To modify a published commit and apply a `Squash-to` patch, the easiest is when
the patch contains the subject of the commit to modify between double quotes. In
this case, you can use:

    ./.am-squash-to-patch.sh <Message-ID>

If not, you can use:

    ./.am-squash-to-patch.sh "<commit title>" <Message-ID>

Or "manually": you first need to switch to the correct branch, see `Find a topic
name` section below. Then you can use `am-patch.sh` and `publish.sh`, e.g.

    git switch t/DO-NOT-MERGE-mptcp-enabled-by-default
    ./.am-patch.sh [<Message-ID> | patch <Patchwork ID> | series <Patchwork ID> | mbox file]
    ./.publish.sh

In case of conflicts during the amend step, you can probably do:

    git am --show-current-patch=diff | patch -p1 --merge
    git add -p
    ./.end-squash.sh


Find a topic name
-----------------

TopGit topic names are based on the original commit title, prepent with `t/`,
e.g. `mptcp: enabled by default` will have its topic called
`t/mptcp-enabled-by-default`.

To list all topics, you can use:

    git checkout t/upstream  ## or t/upstream-net
    tg info --series

To find a specific topic, you can use:

    ./.tg-get-topic.sh "<commit title>"


Send patches upstream
---------------------

Here is a checklist.

* Prerequisite:
  * Set up Git remotes for `mptcp_net-next`, `net`, and `net-next`:

        [remote "origin"]
                url = git@github.com:multipath-tcp/mptcp_net-next.git
                fetch = +refs/heads/*:refs/remotes/origin/*
        [remote "netdev-next"]
                url = git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next
                fetch = +refs/heads/*:refs/remotes/netdev-next/*
        [remote "netdev-net"]
                url = git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net
                fetch = +refs/heads/*:refs/remotes/netdev-net/*

  * Install `b4` and make sure you are at least using the last stable version:

        python3 -m pip install --user --upgrade b4

* Fetch latest `net` and `net-next` changes + either `export` (for `net-next`)
  or `export-net` (for `net`):

        git fetch --multiple netdev-next netdev-net

* Prepare a new branch with one of these adapted commands (with a description):

        b4 prep -n upstream-net-next-$(date +%Y%m%d)-<description> -f netdev-next/main --set-prefixes net-next
        b4 prep -n upstream-net-$(date +%Y%m%d)-<description> -f netdev-net/main --set-prefixes net
        b4 prep -n upstream-stable-$(date +%Y%m%d)-<description> -f stable/linux-6.x.y --set-prefixes 6.x

* Cherry-pick commits you need and add the upstreamer's signoff:

        ./.list-exported-commits.sh
        git cherry-pick -s <...>

* Check for net/net-next conflicts. If possible, defer net-next upstreaming
  until net-branch patches they conflict with have been merged to the net-next
  branch. If it is not possible to wait, document the resolution.

        git branch -f tmp && git switch tmp
        git merge --no-edit netdev-next/main  ## or -net
        git switch -

* Build the code and run tests:

        ./.virtme_upstream.sh

* Send the current version to `git.kernel.org` to get some feedback from Intel's
  lkp:

        git cherry-pick export
        git push matttbe-korg HEAD HEAD:master -f  ## or another remote
        git reset --hard HEAD~

* Double-check Git tags in commit messages:

        git rebase -i $(b4 prep --show-info | awk '/^start-commit: / { print $2 }')..

  * Sender `Signed-off-by` tag should be last, and not duplicated.
  * Typically place `Fixes`, `Reported-by` then `Closes` tags first in the list
  * If the series is for -net (fixes), it is recommended to add
    `Cc: stable@vger.kernel.org` (eventually with `# v<version>+`) on each
    patch:

        ./.append-cc-stable.sh $(b4 prep --show-info | awk '/^start-commit: / { print $2 }')..

* Edit the cover letter, replacing the subject and body placeholders:

        b4 prep --edit-cover

  * Give a quick summary of the included patches. If upstreaming a group of
    patches that implements a whole feature, it's helpful to add a paragraph or
    two explaining the full feature (refer to the original cover letters sent to
    `mptcp@lists.linux.dev` if needed).

  * If upstreaming a collection of unrelated patches, no need to add extra
    explanations, just explain each in the cover letter:

        Patch 1: Fix a bug

        Patches 2-3: Improve self test consistency

        Patch 4: Another bug fix

  * For -net, add which kernels versions have the bugs:

        ./.git-check-fixes.sh $(b4 prep --show-info | awk '/^start-commit: / { print $2 }')..

* Determine cc addresses for the series:

        b4 prep --auto-to-cc

  * If any outdated email addresses are associated with the fixed commit,
    substitute a current address if possible. It helps to add a Git note to the
    commit with `git notes edit <commit>` to document that.

* Run checkpatch one more time (issues should have been caught before but
  sometimes the above edits can add problems):

        ./.checkpatch-b4.sh

* Send the patches to yourself only:

        b4 send --reflect

* If the previous step generated correct emails, send them to the mailing lists:

        b4 send

* Make sure the full series appears in PatchWork in both
  [MPTCP](https://patchwork.kernel.org/project/mptcp/list/) and
  [Netdev](https://patchwork.kernel.org/project/netdevbpf/list/) projects

* Mark the series as `Handled Elsewhere` in MPTCP PatchWork.

* Check CI status in the Netdev PatchWork.

* Monitor for upstream merge or maintainer feedback.


Weekly meetings
---------------

You will also need to install [ghi](https://github.com/stephencelis/ghi) to list
GitHub issues. You might need to manually apply this
[fix](https://github.com/stephencelis/ghi/pull/393/files).

Before a meeting, use:

    ./.list-patches.sh
    ./.list-github.sh
    ./.list-exported-commits.sh

After a meeting, use:

    ./.patch-archive-week.sh

But also send the meeting minutes and update the
[wiki page](https://github.com/multipath-tcp/mptcp_net-next/wiki/Meetings).
