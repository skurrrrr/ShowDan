import re #regular expression
import ssl
import os
import subprocess
import asyncio #make sure to install asyncio. I used: pip3 install asyncio --break-system-package
import json
from OpenSSL import crypto
import aiohttp #module to make parallel requests
import xml.etree.cElementTree as ET
from bs4 import BeautifulSoup, SoupStrainer
# uncomment these if you're going to use the alternate x509 code
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

class SSLChecker:
    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="massscanResults.txt", 
        ips_file="ips.txt", 
        masscan_rate=10000,
        timeout=2,
        chunkSize=2000,MAX_CONCURRENT=100,semaphore_limit=70,protocols=["http://","https://"] #semephore_limit= how many requests at ONE time.
        

    ):
        self.ssl_port=ssl_port
        self.mass_scan_results_file=mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate #defines how fast to run the scan, 10,000 is ideal
        self.timeout=timeout
        self.protocols=protocols
        self.chunkSize=chunkSize
        self.semaphore=asyncio.Semaphore(semaphore_limit)
        self.MAX_CONCURRENT=MAX_CONCURRENT

    def is_valid_domain(self,command_name):
        domain_pattern= r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(domain_pattern,command_name) is not None


    async def makeGetRequest(self,session,protocol,ip,command_name,makeRequestByIP=True):
        async def parseResponse(url,port):
            try:
                if self.semaphore.locked():
                    await asyncio.sleep(1)

                redirected_domain=""
                response_headers={}
                first_300_words=""
                title=""

                async with session.get(url,allow_redirects=True,timeout=self.timeout,ssl=False) as res:
                    response=await res.text(encoding="utf-8")
                    content_type=res.headers.get("Content-Type")

                    if res.headers is not None:
                        for key,value in res.headers.items():
                            response_headers[key] = value.encode("utf-t","surrogatepass").decode("utf-8")

                    if res.history:
                        redirected_domain = str(res.url)

                    if response is not None and content_type is not None:
                        if "xml" in content_type:
                            root = ET.fromstring(response)
                            xmlwords=[]
                            count=0

                            for elem in root.iter():
                                if elem.text:
                                    xmlwords.extend(elem.text.split())
                                    count += len(xmlwords)
                                    if count >= 300:
                                        break
                            if xmlwords:
                                first_300_words = " ".join(xmlwords[:300])

                        elif "html" in content_type:
                            strainer= SoupStrainer(["title","body"])
                            soup= BeautifulSoup(response,"html.parser",parse_only=strainer)
                            title_tag=soup.title
                            body_tag=soup.body

                            if title_tag and title_tag.string:
                                title = title_tag.string.strip()

                            if body_tag:
                                body_text = body_tag.get_text(separator=" ",strip=True)
                                words= body_text.split()
                                first_300_words = " ".join(words[:300])

                            if not body_tag or not title_tag:
                                words= response.split()
                                first_300_words = " ".join(words[:300])

                        elif "plain" in content_type:
                            words= response.split()
                            first_300_words= " ".join(words[:300])

                        elif "json" in content_type:
                            first_300_words = response[:300]

                        if makeRequestByIP:
                            print(f"Title:  {title}, {protocol}{ip}:{port}")
                        else: 
                            print(f"Title:  {title}, {protocol}{command_name}:{port}")

                        result_dict= {
                            "title":title.encode("utf-8","surrogatepass").decode("utf-8"),
                            "request":f"{protocol}{ip if makeRequestByIP else command_name}:{port}",
                            "redirected_url":redirected_domain,
                            "ip":ip,
                            "port":str(port),
                            "domain":command_name,
                            "response_text":first_300_words,
                            "response_headers":response_headers
                        }

                        return result_dict
            except ET.ParseError as e:
                print(f"Error parsing XML: {e}")
                        
            except Exception as e:
                if makeRequestByIP:
                    print(f"Error for: {protocol}{ip}:{port}, {e}")
                else:
                    print(f"Error for: {protocol}{command_name}:{port}, {e}")
            return None

    
    async def check_site(self,session,ip,command_name):
        try:
            async with self.semaphore:
                temp_dict={}

                if "*" in command_name or not self.is_valid_domain(command_name):
                    for protocol in self.protocols:
                        dict_res=awaitself.makeGetRequestToDomain(session,protocol,ip,command_name,True)
                        temp_dict[f'{protocol.replace("://","")}_responseForIP'] = dict_res
                else:
                    # If we found a proper domain name from ssl certificate, then make a request to that domain using http:// and https:// and also make request using IP address so in total 4 requests
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequest(
                            session, protocol, ip, common_name, False
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForDomainName'
                        ] = dict_res

                    # Also make a request using to http:// and https:// using the IP address
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequest(
                            session, protocol, ip, common_name, True
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForIP'
                        ] = dict_res

                    temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
                    if temp_dict:
                        return temp_dict


                
        except Exception as e:
            print("Error for ",ip,":",e)

         # If something goes wrong like a timeout we must return None
        return None

    async def fetch_certificates(self, ip):
        try:
            
            # If the certificate funtion returns error uncomment this  and uncomment the lines below this? Confusing...
            # # cert_data = await asyncio.to_thread(
            #     ssl.get_server_certificate, (ip, 443), ssl_version=ssl.PROTOCOL_TLS
            # )
            # x509_cert = x509.load_pem_x509_certificate(
            #     cert_data.encode(), default_backend()
            # )
            # common_name = x509_cert.subject.get_attributes_for_oid(
            #     x509.NameOID.COMMON_NAME
            # )[0].value

            cert= await asyncio.to_thread(ssl.get_server_certificate,(ip,self.ssl_port),timeout=self.timeout)
            x509=crypto.load_certificate(crypto.FILETYPE_PEM,cert)
            subject= x509.get_subject()
            command_name=subject.CN
            print(command_name)

            return ip,command_name

        except Exception as e:
            print(f"Error for {ip}: {e}")

        return ip,""

    async def extract_domains():
        try:
            with open(self.mass_scan_results_file,"r") as file:
                content=file.read()

            ip_pattern = r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
            ip_addresses = re.findall(ip_pattern, content)

            for i in range(0,len(ip_addresses),self.chunkSize):
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT,ssl=False)) as session:
                    chunk_Of_IPs = ip_addresses[i:i+self.chunkSize]
                    ip_and_common_names=[]

                    ip_and_common_names = await asyncio.gather(*[self.fetch_certificates(ip) for ip in chunk_Of_IPs])

                    allResponses=await asyncio.gather(*[self.check_site(session,ip,command_name) for ip,command_name in ip_and_common_names])



    def run_masscan(self):
        try:
            # this rate limit is the ideal to get the maximum amount of ip addresses
            command = f"sudo masscan -p443 --rate {self.masscan_rate} --wait 0 -iL {self.ips_file} -oH {self.mass_scan_results_file}"
            subprocess.run(command, shell=True, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")
        except FileNotFoundError:
            print("Masscan executable not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def check_and_create_files(self,*file_paths):
        for file_path in file_paths:
            if not os.path.exists(file_path):
                #If the file doesn't exist, create it
                with open(file_path,"w") as file:
                    pass
                print(f'File "{file_path}" has been created')


    async def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()
        await self.extract_domains() #uses an asyncronous method, hence "await"

if __name__=="__main__":
    ssl_checker = SSLChecker()
    asyncio.run(ssl_checker.main()) #creates a new event loop for the duration of the call, then closes it after function is concluded