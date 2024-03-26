import os
import platform
import subprocess
import random
import time
class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    CWHITE = '\33[37m'
FileLockDownCommands = [
    'sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow',
    'sudo chown root:root /etc/group && sudo chmod 644 /etc/group',
    'sudo chown root:shadow /etc/gshadow && sudo chmod 640 /etc/gshadow',
    'sudo chown root:root /etc/security/opasswd && sudo chmod 600 /etc/security/opasswd',
    'sudo chown root:root /etc/passwd- && sudo chmod 600 /etc/passwd-',
    'sudo chown root:root /etc/shadow- && sudo chmod 600 /etc/shadow-',
    'sudo chown root:root /etc/group- && sudo chmod 600 /etc/group-',
    'sudo chown root:root /etc/gshadow- && sudo chmod 600 /etc/gshadow-'
]
Passwords=['Zeus','Athena','Apollo','Anubis','Medusa','Odin','Hercules','Aphrodite','Poseidon','Krishna','Ra','Shiva','Hades','Freyja','Persephone','Loki','Artemis','Osiris','Horus','Ganesh','Amaterasu','Fenrir','Hera','Kali','Baldur','Quetzalcoatl','Durga','Thor','Hestia','Gaea','Uranus','Pontus','Horus','Atlas','Oceanus','Cronus','Nyx','Zephyrus','Morpheus','Pallas','Pontus','Tartarus','Ares','Castor','Chaos','Crios','Dionysus','Helios','Hyperion','Hypnos']
characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+'
def main():
    MyOS=platform.system()
    Me = subprocess.Popen(['whoami'], shell=True, stdout=subprocess.PIPE).stdout.read()
    WhoAmI= subprocess.Popen(['who am i'], shell=True, stdout=subprocess.PIPE).stdout.read()
    default_gateway = next(line.split()[2] for line in (subprocess.Popen(['ip route'], shell=True, stdout=subprocess.PIPE).stdout.read()).splitlines() if 'default' in line)
    WhoAmI = WhoAmI.decode().strip().split()
    username = WhoAmI[0]
    terminal_line = WhoAmI[1]
    login_time = ' '.join(WhoAmI[2:5])
    ip_address = WhoAmI[5][1:-1]
    print('''Detected: {}{}{}
            Running As: {}{}{}
            Username: {}{}{}
            Terminal Line: {}{}{}
            Login Time: {}{}{}
            IP Address: {}{}{}
        Defualt Gateway: {}{}{}'''.format(color.CYAN, MyOS, color.END, color.GREEN, Me, color.END, color.GREEN, username, color.END, color.PURPLE, terminal_line, color.END, color.PURPLE, login_time, color.END, color.PURPLE, ip_address, color.END,color.YELLOW, default_gateway, color.END))
def lockdown_shadow(): 
    for command in FileLockDownCommands:
            subprocess.Popen(command, shell=True)

def password_reset():
    passwd_output = subprocess.check_output(['cut', '-d:', '-f1', '/etc/passwd'])
    users = passwd_output.split('\\n')
    users.remove('')
    for account in users:
        new_password=random.choice(Passwords)+'_'+''.join(random.choice(characters) for _ in range(6))
        errormessage=subprocess.Popen(['passwd', account], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True).communicate(input=new_password +'\\n'+new_password + '\\n')
        print('''User: {}{}{} \\n>>Password: {}{}{}''').format(color.YELLOW, account, color.END,color.YELLOW, new_password, color.END)
        #time.sleep(1)
        #if(account.strip()!=username.strip() and account.strip() !='root'):
            #stupid_shit=subprocess.Popen(['passwd', '-l', account])
                #print('''{}ERROR:{}{}\\nUnable to change Lock User: {}{}{}''').format(color.RED, e,color.END,color.RED,account, color.END)
        