# Contributing

## Getting Started

Sign up to the [Open Privacy Gogs instance](https://git.openprivacy.ca/)

Get the code

    clone gogs@git.openprivacy.ca:cwtch.im/cwtch.git
    
Make a development branch to do your work

    git checkout -b work-branch-name
    
If you are using Goland as an IDE, now would be a good time to enable automatic gofmt on save of files with the File Watches plugin [https://stackoverflow.com/questions/33774950/execute-gofmt-on-file-save-in-intellij](StackOverflow)

## Pull Requests

When you are done, rebase squash any multiple commits you have into one

    git rebase -i master
    
Test the code and check it has not quality issues

    ./testing/tests.sh
    ./testing/quality.sh
    
Ideally run the integration tests (~5 minutes)

    cd testing
    go test
    
push your branch (-f for *force* in the case you've rebased and squashed)

    git push origin work-branch-name -f
    
create a [pull request](https://git.openprivacy.ca/cwtch.im/cwtch/pulls)

If you have fixes, you can amend them to the current commit rather than a new one with

    git commit --amend
    git push -f

## Review Board

For very large and complicated Pull Requests we have created a Review Board instance to facilitate more in depth review and discussion at https://review.openprivacy.ca

First acquire the client, RBTools, on Ubuntu:

    apt install rbtools

Then hookup your git repo to review board with:    

    rbt setup-repo

Using the repo `cwtch`

Finally you will be able to create commits with

    rbt post --parent master

It possibly will need the arguments `--tracking-branch=cwtch/master --branch=YOUR-BRANCH -d` (-d for debug if you are having trouble)
