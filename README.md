# GraphQL-UF
GraphQL UF is a Burp Suite extension designed to help penetration testers and security researchers identify and analyze unique GraphQL operations intercepted during testing. It automatically scans your proxy history, extracts distinct GraphQL queries and mutations, and presents them in an easy-to-navigate UI.

**Features**
* Automatic scanning of Burp Proxy history for GraphQL requests.
* Identification and listing of unique GraphQL operations by query hash.
* Display of essential metadata: HTTP method, request URL, operation name.
* Search/filter operations by name in real-time.
* Request and response viewers for inspecting HTTP traffic.
* Context menu with options to:
  * Send selected request to Repeater for further manual testing.
  * Clear selected request from the list.
  * Clear all requests with confirmation.
* Sorting by ID or any column.
* Clean and intuitive Swing-based GUI tab inside Burp Suite.

**Installation**
* Download the latest release .py file from the Releases.
* Open Burp Suite.
* Go to the Extensions tab.
* Click Add.
* Select Extension type: Python.
* Load the .jar file as your Burp extension.
* The GraphQL UF tab will appear in Burp Suite.
  
**Usage**
* Navigate to the GraphQL UF tab.
* Click the Start button to scan your proxy history for GraphQL operations.
* View unique GraphQL queries/mutations in the table.
* Use the Search box to filter operations by name.
* Select a row to view its request and response.
* Right-click a row to:
  * Send the request to Repeater.
  * Clear the specific row.
* Use the Clear All button to clear the entire list (with confirmation).

**Requirements**
* Burp Suite (Community or Professional)
* Jython standalone JAR (for running Python extensions)
* Java 8 or above

Feel free to reach out for questions or collaboration!
