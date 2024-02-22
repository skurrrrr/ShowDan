import os
import subprocess

class SSLChecker:
    def __init__(
        self,
        mass_scan_results_file="massscanResults.txt", 
        ips_file="ips.txt", 
        masscan_rate=10000
    ):
        self.mass_scan_results_file=mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate #defines how fast to run the scan, 10,000 is ideal

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


    def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()


if __name__=="__main__":
    ssl_checker = SSLChecker()
    ssl_checker.main()