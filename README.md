# reddit-bot

This is a bot made for the /r/C_Programming subreddit.  It copies the text of an original post as a comment.

A build.sh script is provided.  Currently only tested on Linux but should also work on other platforms.  Only dependecy is libcurl.

Credentials are read from a file named "credentials" (not provided in this repo).  The file must be in the following format, seperated by newlines.

App Id
App Secret
Reddit Username
Reddit Password

The app id and secret can be obtained by registering the app here: https://ssl.reddit.com/prefs/apps/
