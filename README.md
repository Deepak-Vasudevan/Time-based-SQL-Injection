# Time-based-SQL-Injection

A simple python program to identify vulnerable urls suseptible to time-based SQL injection attacks.

### *Objective:*

Blind SQL injection vulnerabilities on web applications are identified by treating the application like a black-box and measuring the response time to such attacks. In case of a considerable delay in the response, it could be determined that the delay is due to the payload being executed on the server and hence the application is vulnerable. Given the time-dependent nature of the tests, the validation is prone to false positives that may have been caused by a network delay or some other server delay and not due to the payload execution. This results in the website being classified as vulnerable when it may not be so. This program tries to efficiently identify and classify the web application as being vulnerable only when the delay is caused by executing the payload in the server.

### *Implementation:*

A general implementation could involve executing a set of requests with different sleep durations and measuring the time difference between the sets. A vulnerability is determined if there is a definitive pattern observed between the execution times. The network delay introduced is eliminated by statistically comparing the difference in the delay profiles. However, this still could require several requests with a varying injected delay to be executed on the application server. While this is statistically efficient in identifying vulnerable urls, the safe urls also need to execute all the requests to establish a safe pattern. The problem, therefore, is dependent more on the network delay and not the sql injection.

The problem focuses on modelling the instantaneous network delay and then injecting the time delay to test for the vulnerability. This is achieved by designing the algorithm to generate one set containing 5 regular requests to measure the network delay, and another set of 5 requests with the delay injection to identify the vulnerability.

### *Considerations:*

The algorithm is intended to detect only sql-injection attacks. For the purpose of testing on different urls, a testing set is generated with random page numbers and ids within the code. In addition, for the purpose of evaluation, each of the generated urls are classified as safe or vulnerable using flags to determine the number of false positives. The application server is mimicked by using a flask container on the local host and introducing a random network delay for all urls. The vulnerable urls have an additional delay introduced in correspondance to the delay mentioned in the payload.   
