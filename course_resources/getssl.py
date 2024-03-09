import re
import ssl
import os
import subprocess
import asyncio
from OpenSSL import crypto
import aiohttp

class SSLChecker:
    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips.txt",
        masscan_rate=10000,
        timeout=2,
        chunkSize=2000,MAX_CONCURRENT=100

    ):
        self.ssl_port=ssl_port
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.timeout=timeout
        self.chunkSize=chunkSize
        self.MAX_CONCURRENT=MAX_CONCURRENT


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

    async def extract_domains():
        try:
            with open(self.mass_scan_results_file, "r") as file:
                content = file.read()

            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            ip_addresses = re.findall(ip_pattern, content)


            for i in range(0,len(ip_addresses),self.chunkSize):
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT, ssl=False)) as session:
                    chunk_Of_IPs = ip_addresses[i:i+self.chunkSize]
                    ip_and_common_names=[]

                    ip_and_common_names = await asyncio.gather(*[self.fetch_certificate(ip) for ip in chunk_Of_IPs])
                        
                

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
    ssl_checker.main()
