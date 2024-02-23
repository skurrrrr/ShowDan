import re #regular expression
import os
import subprocess
import asyncio #make sure to install asyncio. I used: pip3 install asyncio --break-system-package
import aiohttp #module to make parallel requests

class SSLChecker:
    def __init__(
        self,
        ssl_port=443,
        mass_scan_results_file="massscanResults.txt", 
        ips_file="ips.txt", 
        masscan_rate=10000,
        timeout=2,
        chunkSize=2000

    ):
        self.ssl_port=ssl_port
        self.mass_scan_results_file=mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate #defines how fast to run the scan, 10,000 is ideal
        self.timeout=timeout
        self.chunkSize=chunkSize


    async def fetch_certificates(self, ip):
        try:
            cert= ssl.
        except Exception as e:
            print(f"Error for {ip}: {e}")

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




    def run_masscan(self): # p443=port, rate=rate, wait 0 =don't wait on timeout, -iL=output -oH=where to save results
        try:
            command = f"sudo masscan -p443 --rate {self.masscan_rate} --wait 0 -iL {self.ips_file} -oH {self.mass_scan_results_file}"
            subprocess.run(command, shell=True, check=True) #spawns process so we can run exteral application (massscan) in subprocess, addit shell parameter lets you use pipe and stuff, Check=True outputs more verbose errors
        
        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")

        except FileNotFoundError:
            print("Masscan executable not found")

        except Exception as e:
            print(f"An unexpected error occured: {e}")

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
    ssl_checker.main()