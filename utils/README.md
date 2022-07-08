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
same if you need to place a patch before a specific topic (Git branch). Check
the `Find a topic name` section below.

In case of conflicts, please follow the intructions and use `./.end-conflict.sh`.


Amend of topic (Apply a `Squash-to` patch)
------------------------------------------

To modify a published commit and apply a `Squash-to` patch, you first need to
checkout on the correct branch, see `Find a topic name` section below. Then
you can use `am-patch.sh` and `publish.sh`, e.g.

    git checkout t/DO-NOT-MERGE-mptcp-enabled-by-default
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


Send patches upstream
---------------------

`send-upstream.sh` script can be used but Mat has probably more scripts to share
and document here.


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
