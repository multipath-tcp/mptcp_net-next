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

`send-upstream.sh` script can be used, but most of our upstreaming has been done manually. For the manual process:

* Prerequisite: Set up git remotes for mptcp_net-next, net, and net-next
* Check out a local branch that's a copy of either export (for net-next) or export-net (for net)
* Fetch latest net and net-next changes 
* Do an interactive rebase to remove extra commits and add the upstreamer's signoff

      git-rebase -i --signoff net/main  ## or net-next/main

* Double-check git tags. Sender signoff should be last, and not duplicated. Reviewed-by/Acked-by precede the signoffs. Typically place Closes and Fixes tags first in the list, and make sure all -net patches have a Fixes tag. Keep Reviewed-by tags from the sender if they are present, even if it's redundant with the signoff.
  * Properly formatted Fixes tags can be generated easily if you add the following block to your .gitconfig:

        [pretty]
            fixes = Fixes: %h (\"%s\")

  * This allows generating the "Fixes: " tag with

        git log --pretty=fixes <commit-id>

* Build the code and run tests.
* Check for net/net-next conflicts. If possible, defer net-next upstreaming until net-branch patches they conflict with have been merged to the net-next branch.
* Determine cc addresses for the series.
  * Always include netdev maintainers (davem@davemloft.net kuba@kernel.org pabeni@redhat.com edumazet@google.com), MPTCP maintainers (matthieu.baerts@tessares.net mathew.j.martineau@linux.intel.com), and mptcp@lists.linux.dev
  * For patches with Fixes tags, also cc the author **and any co-developers** of the fixed commit. `scripts/get_maintainers.pl --email --fixes` (from the kernel repo, not the special scripts branch this README is in) will look this up for you, and is what the netdev CI will run and check against. If any outdated email addresses are associated with the fixed commit, substitute a current address if possible. It helps to add a note to the .patch file (add an extra `---` after the git tags in the relevant .patch file and then add text that will not be imported in to git).
* Format the patches (add any relevant `--cc` flags), replacing `-N` with the appropriate number of patches:

      git format-patch -N --to=netdev@vger.kernel.org --cc=davem@davemloft.net --cc=kuba@kernel.org --cc=pabeni@redhat.com --cc=edumazet@google.com --cc=matthieu.baerts@tessares.net --cc=mptcp@lists.linux.dev --cover-letter --base=net/main --subject-prefix="PATCH net"
      ## or
      git format-patch -N --to=netdev@vger.kernel.org --cc=davem@davemloft.net --cc=kuba@kernel.org --cc=pabeni@redhat.com --cc=edumazet@google.com --cc=matthieu.baerts@tessares.net --cc=mptcp@lists.linux.dev --cover-letter --base=net-next/main --subject-prefix="PATCH net-next"
      
* Edit the cover letter, replacing the subject and body placeholders.
  * Give a quick summary of the included patches. If upstreaming a group of patches that implements a whole feature, it's helpful to add a paragraph or two explaining the full feature (refer to the original cover letters sent to mptcp@lists.linux.dev as needed).
  * If upstreaming a collection of unrelated patches, no need to add extra explanation, just explain each in the cover letter:

        Patch 1: Fix a bug
        
        Patches 2-3: Improve self test consistency
        
        Patch 4: Another bug fix
        
* Run the .patch files through checkpatch one more time if you want (CI should have caught issues in the code, but sometimes the above edits can add a problem).

        scripts/checkpatch.pl *.patch
        
* Send the patches (assuming there are no extra patch files sitting around...)

        git send-email *.patch
        
* Make sure the full series appears in both https://patchwork.kernel.org/project/mptcp/list/ and https://patchwork.kernel.org/project/netdevbpf/list/
* Mark the series as "Handled Elsewhere" in MPTCP patchwork.
* Check CI status in the netdev patchwork.
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
