# A DNS probing Tool
A dns probing tool which shows your DNS resolver IPs and latancy.

It can also test if your browser supports HTTP3 and shows your IP addresses.

See the scheme image below for technical details.

# Demo
See the demo here: [https://probe.xxyy.app/](https://probe.xxyy.app/)

# Scheme
![The scheme image](scheme.jpg)

```
T1 - T0 =  HTTP_Downward_Time + Browser_DNS_Delay

T2 - T1 =  DNS_Downward_Time + HTTP_Upward_Time

T3 - T2 =  HTTP_Downward_Time + HTTP_Upward_Time

Where

Browser_DNS_Delay is the time between browser starts loading and DNS resolver receives request.

DNS_Downward_Time is the time between DNS resolver responds and Browser gets the response.

Both account for DNS overhead.


Browser_DNS_Delay + DNS_Downward_Time = (T2 - T0) - (T3 - T2)

if assume HTTP_Downward_Time = HTTP_Upward_Time, then

  Browser_DNS_Delay = ( T1 - T0) - (T3 - T2)/2

  DNS_Downward_Time = ( T2 - T1) - (T3 - T2)/2
```
