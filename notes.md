Okay, so:

clone masscan
writh some of the python code (kind of steezy)
 - fixed an error (exits instead of exists)

Gloss over IP subnet stuff
 - use bgp.he.net to get company subnets
 - use tunnelsup.com/subnet-calculator to calculate subnets
 - use whois.com to see... who is

Install jp:
sudo apt-get install jq
Then run this to parse ip addresses from gstatic.com into a text file: 
 #had to change a ' to "
 
 curl -s https://www.gstatic.com/ipranges/cloud.json | jq -r ".prefixes[] | select(.ipv4Prefix != null) | .ipv4Prefix" > googleIPs.txt

Run this to get AWS ips:
#I had to look up where to get the IP json, the class link didn't work

curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[].ip_prefix' > AWS.txt

test
