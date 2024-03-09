import re
import ssl
import os
import subprocess
import asyncio
from OpenSSL import crypto
import aiohttp
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

class SSLChecker:
    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips.txt",
        masscan_rate=10000,
        timeout=2,
        chunkSize=2000,MAX_CONCURRENT=100,semaphore_limit=70,protocols=["http://","https://"]

    ):
        self.ssl_port=ssl_port
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.protocols=protocols
        self.timeout=timeout
        self.chunkSize=chunkSize
        self.semaphore=asyncio.Semaphore(semaphore_limit)
        self.MAX_CONCURRENT=MAX_CONCURRENT


    def is_valid_domain(self,common_name):
        domain_pattern=  r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(domain_pattern,common_name) is not None
        

    
    async def check_site(self, session, ip, common_name):
        try:
            async with self.semaphore:
                temp_dict = {}

                if "*" in common_name or not self.is_valid_domain(common_name):
                    # If there is an asterisk in the common_name then make a request to the IP address, but sometimes if we use http://ip we get a different result and sometimes if we use https://ip we get a different result so we make HTTP and HTTPS requests for the IP so 2 requests in total
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequestToDomain(
                            session, protocol, ip, common_name, True
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForIP'
                        ] = dict_res

                else:
                    # If we found a proper domain name from ssl certificate, then make a request to that domain using http:// and https:// and also make request using IP address so in total 4 requests
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequestToDomain(
                            session, protocol, ip, common_name, False
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForDomainName'
                        ] = dict_res

                    # Also make a request using to http:// and https:// using the IP address
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequestToDomain(
                            session, protocol, ip, common_name, True
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForIP'
                        ] = dict_res

                # Filter out None values from temp_dict
                temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
                # Only append non-empty dictionaries to the results
                if temp_dict:
                    return temp_dict

        except Exception as e:
            print("Error for", ip, ":", e)
            pass

        # If something goes wrong like a timeout we must return None
        return None


    async def fetch_certificate(self,ip):
        try:
            # cert_data = await asyncio.to_thread(
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
            common_name=subject.CN
            print(common_name)
            
            return ip,common_name

        except Exception as e:
            print(f"Error for {ip}: {e}")

        return ip,""

    async def extract_domains(self):
        try:
            with open(self.mass_scan_results_file, "r") as file:
                content = file.read()

            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            ip_addresses = re.findall(ip_pattern, content)

            for i in range(0, len(ip_addresses), self.chunkSize):
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT, ssl=False)
                ) as session:
                    chunk_Of_IPs = ip_addresses[i : i + self.chunkSize]
                    ip_and_common_names = []

                    ip_and_common_names = await asyncio.gather(
                        *[self.fetch_certificate(ip) for ip in chunk_Of_IPs]
                    )

                    allResponses = await asyncio.gather(
                        *[
                            self.check_site(session, ip, common_name)
                            for ip, common_name in ip_and_common_names
                        ]
                    )
                

    def run_masscan(self):
        try:
            command = f"sudo masscan -p443 --rate {self.masscan_rate} --wait 0 -iL {self.ips_file} -oH {self.mass_scan_results_file}"
            subprocess.run(command, shell=True, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")

        except FileNotFoundError:
            print("Masscan executable not found")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def check_and_create_files(self, *file_paths):
        for file_path in file_paths:
            if not os.path.exists(file_path):
                # If the file doesn't exist,create it
                with open(file_path, "w") as file:
                    pass
                print(f'File "{file_path}" has been created')

    async def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()
        await self.extract_domains()


if __name__ == "__main__":
    ssl_checker = SSLChecker()
    asyncio.run(ssl_checker.main())
