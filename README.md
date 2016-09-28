Project: Multi User Blog  - [Shumei Lin]
================================

Required Libraries and Dependencies
-----------------------------------
Requires javascript on the browser.

To run locally:
Requires python v2.7 and Google App Engine Launcher to be installed.

How to Run Project
------------------
Go to http://basicblog-1378.appspot.com to view the website.

To run locally:
After download the project file, unzip the project file. Open Google App Engine Launcher, from "File" select "Add Existing Application" and choose the unzipped project file. After project is added to the Google App Engine Launcher, click "Run". When application is successfully compiled, click "Browse".From there you can see the website running on local host.

Miscellaneous
-------------
I used gql queries to retrieve blog posts and comments to be displayed on the website. After users delete a blog post or a comment, or like a blog post, they are immediately redirected to the home page or the blog post page. However, due to google datastore's Eventual Consistency, items changes to the datastore may take a moment before they are visible to queries. In that case, users need to manually refresh the page to view changes of deletions or editions. Therefore, I added a simple javascript function to make the webpage refresh once when it is first loaded to resolve this issue.