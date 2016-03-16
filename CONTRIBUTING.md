# Contributing to Openmaize

The first part of this document covers the goals and the scope of Openmaize,
and then lists some ways that developers can contribute to it.

After that, there is more technical information about the contributing
process.

## Features

* handles login / logout
* authenticates users using JSON Web Tokens
* provides excellent documentation
* is framework-agnostic
* is lightweight

## Ways you can contribute

* Find bugs
* Add to, or improve, the documentation
* Add further plugs / checks you think might be useful

## Bug reports

Guidelines for bug reports:

1. **Use the GitHub issue search** &mdash; check if the issue has already been
   reported.

2. **Check if the issue has been fixed** &mdash; try to reproduce it using the
   `master` branch in the repository.

3. **Report the problem** &mdash; open an issue.

Please try to be as detailed as possible in your report. Include information about
your Operating System, as well as your Erlang and Elixir versions. Please provide steps to
reproduce the issue as well as the outcome you were expecting. Also include any error messages
that you get. All these details will help developers to fix any potential bugs.

## Feature requests

First, make sure that the feature fits in with the goals of Openmaize. Then,
open an issue explaining what feature you would like implemented. Please
provide technical / practical details about why this feature is needed.

**IMPORTANT**: Remember that you need to convince us that this feature is needed.

## Contributing documentation

Documentation is a very important part of the whole Openmaize package. The
documentation is not limited to how a module or function works, but also
provides, succintly and clearly, more general information related to the
aims of this project, such as authentication, authorization, JSON
Web Tokens, etc.

If you are contributing documentation that makes any claims, for example,
that something is faster, more secure, etc., please provide link(s) to the
sources of this information.

## Pull requests

Good pull requests - patches, improvements, documentation, new features - are
a fantastic help. They should remain focused in scope and avoid containing
unrelated commits.

**IMPORTANT**: By submitting a patch, you agree that your work will be
licensed under the license used by the project.

If you have any large pull request in mind (e.g. implementing features,
refactoring code, etc), **please ask first** otherwise you risk spending
a lot of time working on something that the project's developers might
not want to merge into the project.

Please adhere to the coding conventions in the project (indentation,
accurate comments, etc.) and don't forget to add your own tests and
documentation. When working with git, we recommend the following process
in order to craft an excellent pull request:

1. [Fork](http://help.github.com/fork-a-repo/) the project, clone your fork,
   and configure the remotes:

   ```bash
   # Clone your fork of the repo into the current directory
   git clone https://github.com/<your-username>/openmaize
   # Navigate to the newly cloned directory
   cd openmaize
   # Assign the original repo to a remote called "upstream"
   git remote add upstream https://github.com/elixircnx/openmaize
   ```

2. If you cloned a while ago, get the latest changes from upstream:

   ```bash
   git checkout master
   git pull upstream master
   ```

3. Create a new topic branch (off of `master`) to contain your feature, change,
   or fix.

   **IMPORTANT**: Making changes in `master` is discouraged. You should always
   keep your local `master` in sync with upstream `master` and make your
   changes in topic branches.

   ```bash
   git checkout -b <topic-branch-name>
   ```

4. Commit your changes in logical chunks. Keep your commit messages organized,
   with a short description in the first line and more detailed information on
   the following lines. Feel free to use Git's
   [interactive rebase](https://help.github.com/articles/interactive-rebase)
   feature to tidy up your commits before making them public.

5. Make sure all the tests are still passing.

   ```bash
   mix test
   ```

6. Push your topic branch up to your fork:

   ```bash
   git push origin <topic-branch-name>
   ```

7. [Open a Pull Request](https://help.github.com/articles/using-pull-requests/)
    with a clear title and description.

8. If you haven't updated your pull request for a while, you should consider
   rebasing on master and resolving any conflicts.

   **IMPORTANT**: _Never ever_ merge upstream `master` into your branches. You
   should always `git rebase` on `master` to bring your changes up to date when
   necessary.

   ```bash
   git checkout master
   git pull upstream master
   git checkout <your-topic-branch>
   git rebase master
   ```

Thank you for your contributions!
