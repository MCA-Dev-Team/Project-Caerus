import os
import platform
import subprocess
import random
import re
import time
from threading import Thread
class Color:
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
banner_path = '/etc/ssh/banner'
FileLockDownCommands = [
    'chown root:shadow /etc/shadow && chmod 640 /etc/shadow',
    'chown root:root /etc/group && chmod 644 /etc/group',
    'chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow',
    'chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd',
    'chown root:root /etc/passwd- && chmod 600 /etc/passwd-',
    'chown root:root /etc/shadow- && chmod 600 /etc/shadow-',
    'chown root:root /etc/group- && chmod 600 /etc/group-',
    'chown root:root /etc/gshadow- && chmod 600 /etc/gshadow-',
    ''
]
Art='''
   _             _             _
  | |{}___________{}| |{}___________{}| |
  | |{}___________{}| |{}___________{}| |
  | |           | |           | |
  | |           | |           | |
  | |{}___________{}| |{}___________{}| |
  | |{}___________{}| |{}___________{}| |
  | |           | |           | |
  | |           | |           | |
  <<<<<<<<<<<{}Blue Screen{}>>>>>>>>>
'''.format(Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END,Color.BLUE,Color.END)
Passwords = ['Zeus', 'Athena', 'Apollo', 'Anubis', 'Medusa', 'Odin', 'Hercules', 'Aphrodite', 'Poseidon', 'Krishna',
             'Ra', 'Shiva', 'Hades', 'Freyja', 'Persephone', 'Loki', 'Artemis', 'Osiris', 'Horus', 'Ganesh',
             'Amaterasu', 'Fenrir', 'Hera', 'Kali', 'Baldur', 'Quetzalcoatl', 'Durga', 'Thor', 'Hestia', 'Gaea',
             'Uranus', 'Pontus', 'Horus', 'Atlas', 'Oceanus', 'Cronus', 'Nyx', 'Zephyrus', 'Morpheus', 'Pallas',
             'Pontus', 'Tartarus', 'Ares', 'Castor', 'Chaos', 'Crios', 'Dionysus', 'Helios', 'Hyperion', 'Hypnos']

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+'
DefaultGateway = '192.168.1.1'

def main():
    print(Art)
    MyOS = platform.system()
    Me = subprocess.Popen(['whoami'], shell=True, stdout=subprocess.PIPE).stdout.read()
    WhoAmI = subprocess.Popen(['who am i'], shell=True, stdout=subprocess.PIPE).stdout.read()
    default_gateway = next(line.split()[2] for line in (subprocess.Popen(['ip route'], shell=True,
                                                                      stdout=subprocess.PIPE).stdout.read()).splitlines() if 'default' in line)
    WhoAmI = WhoAmI.decode().strip().split()
    username = WhoAmI[0]
    terminal_line = WhoAmI[1]
    login_time = ' '.join(WhoAmI[2:5])
    ip_address = WhoAmI[5][1:-1]
    print('''Detected: {}{}{}\\nRunning As: {}{}{}Username: {}{}{}\\nTerminal Line: {}{}{}\\nLogin Time: {}{}{}\\nIP Address: {}{}{}\\nDefault Gateway: {}{}{}'''.format(Color.CYAN, MyOS, Color.YELLOW, Color.GREEN, Me, Color.YELLOW, Color.GREEN,
                                           username, Color.YELLOW, Color.PURPLE, terminal_line, Color.YELLOW, Color.PURPLE,
                                           login_time, Color.YELLOW, Color.PURPLE, ip_address, Color.YELLOW, Color.BLUE,
                                           default_gateway, Color.END))
    #MENU
    try:
        while True:
            Options=get_specific_input(int,'{}Choose from the Following options:{}\\n1 : Run Lockdown\\n2 : Configure Services\\n3 : Play Wack-a-Red-Teamer\\n0 : Run Internal Console{}\\n>>>'.format(Color.YELLOW,Color.CYAN,Color.END))
            if Options==0:
                try:
                    while True:
                        os.system(get_specific_input(str,'{}BlueScreen>>>{}'.format(Color.BLUE,Color.END)))
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
                
            if Options==1:#Standard Lockdown
                    command_thread = Thread(target=UpdateServices)
                    command_thread.start()
                    pkill_other_users(username,terminal_line,True)
                    print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW,Color.RED,Color.END))
                    password_reset()
                    pkill_other_users(username,terminal_line,True)
                    print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW,Color.RED,Color.END))
                    lockdown_shadow_and_root()
                    print('''{}etc/Shadow&Passwd&Group: {}Secured{}'''.format(Color.YELLOW,Color.GREEN, Color.END))
                    banner_message = '''{}Hello {}Red Team{}, I sense your woe,\\nYet for {}Trevor's soul{}, I must go.\\nIn this battle's tide, I'll take control,\\nWhen I'm done, you'll pay the toll.{}\\n'''.format(Color.YELLOW,Color.RED,Color.YELLOW,Color.PURPLE,Color.YELLOW,Color.END)
                    create_ssh_banner(banner_message, banner_path)
                    update_ssh_config(banner_path,username)
                    print('{}SSHd Config:{} Updated.{} Banner path: {}. Only {} can SSH.'.format(Color.YELLOW,Color.GREEN,Color.END,banner_path, Color.GREEN+username+Color.END))
                    print('{}Services Update:{} Waiting for Update Thread'.format(Color.YELLOW,Color.END))
                    print('{}Services Update:{} Update Complete{}'.format(Color.YELLOW, Color.GREEN,Color.END))
                    config_firewall(ip_address,DefaultGateway,username)
                    print('''IPv4 Firewall: {}Enabled{}'''.format(Color.GREEN, Color.END))
                    Errors=Install_IpTables_Persist()
                    if Errors:
                        print('Errors occurred during update:')
                        for error in Errors:
                            print(Color.RED + 'Error: ' + Color.END + error)
                        Errors=[]
                    disable_ipv6()
                    print('''IPv6: {}Disabled{}'''.format(Color.RED, Color.END))
                    print('''IPv4 Firewall: {}Config Saved{}'''.format(Color.CYAN, Color.END))
                    command_thread.join()
                    if Errors:
                        print('Errors occurred during update:')
                        for error in Errors:
                            print(Color.RED + 'Error: ' + Color.END + error)
                        Errors=[]
                    pkill_other_users(username,terminal_line,True)
                    print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW,Color.RED,Color.END))
            if Options==2:#Custom Config
                try:
                    while True:
                        ConfigOptions=get_specific_input(int,'{}Choose from the Following options:{}\\n1 : Configure SSH\\n2 : Configure Firewall\\n3 : Lockdown Shadow and Root\\n4 : Update All Services\\n5 : Change all Passwords{}\\n>>>'.format(Color.YELLOW,Color.CYAN,Color.END))
                        if ConfigOptions==1:
                                create_ssh_banner(get_specific_input(str,'Enter New Banner: '),banner_path)
                                update_ssh_config(banner_path,get_specific_input(str,'Enter allowed Users Seperated by ,: '))
                        if ConfigOptions==2:
                                config_firewall(ip_address,DefaultGateway,username)
                                disable_ipv6()
                                print('''IPv6: {}Disabled{}'''.format(Color.RED, Color.END))
                                print('''IPv4 Firewall: {}Config Saved{}'''.format(Color.CYAN, Color.END))
                        if ConfigOptions==3:
                                lockdown_shadow_and_root()
                        if ConfigOptions==4:
                                UpdateServices()
                        if ConfigOptions==5:
                                password_reset()
                        
                            
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
            if Options==3:#Wack a Red Teamer
                try:
                    IHaveFriendlies=get_specific_input(bool_check,'I have Non-Friendlies on my account, true/false: ')
                    print('{}Scanning For All {} Non-Friendlies{}.'.format(Color.YELLOW,Color.RED,Color.END))
                    while True:
                        #time.sleep(0.1)
                        pkill_other_users(username,terminal_line,IHaveFriendlies)
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
            else:
                print('Please Choose a valid option')
    except KeyboardInterrupt:
        print('Exiting BlueScreen')

def pkill_other_users(username, terminal_line, No_Friendlies):
    while True:
        Enemy=0
        who_output = subprocess.Popen(['who'], stdout=subprocess.PIPE).communicate()[0].decode().split('\\n')
        for line in who_output:
            user_info = line.split()
            if len(user_info) < 2:
                continue
            if username == user_info[0]:
                if No_Friendlies:
                    if user_info[1] == terminal_line:
                        continue
                    else:
                        pass
                else:
                    continue
                
            Enemy+=1
            BeGone=['<<< Exterminate! >>>','<<<Resistence Is Futile>>>','<<<We are the Borg. You will be assimilated. Resistance is futile.>>>','<<<Bite Me>>>']
            message = random.choice(BeGone)
            write_process = subprocess.Popen(['write', '{}'.format(user_info[0]),'{}'.format(user_info[1])], stdin=subprocess.PIPE)
            write_process.communicate(input=message.encode())
            subprocess.call(['pkill', '-t', user_info[1]])
            print('{}Exterminated:{} User {} on {}'.format(Color.RED, Color.END, user_info[0], user_info[1]))
        if Enemy==0:
            break

            
def Install_IpTables_Persist():
    Errors=[]
    # Suppress output of subprocesses and capture Errors
    with open(os.devnull, 'w') as devnull:
        try:
            subprocess.check_call('echo \'iptables-persistent iptables-persistent/autosave_v4 boolean true\' |  debconf-set-selections', shell=True, stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))

        try:
            subprocess.check_call('echo \'iptables-persistent iptables-persistent/autosave_v6 boolean true\' |  debconf-set-selections', shell=True, stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))

        try:
            subprocess.check_call('apt-get install iptables-persistent -y', shell=True, stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))
    # Print any captured Errors
        # Save the updated rules
    with open('/etc/iptables/rules.v4', 'w') as rules_file:
        subprocess.Popen(['iptables-save'], stdout=rules_file)
    return Errors
def UpdateServices():
    # Suppress output of subprocesses and capture Errors
    Errors=[]
    with open(os.devnull, 'w') as devnull:
        try:
            subprocess.check_call([ 'apt-get', 'update', '-y'], stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))
        try:
            subprocess.check_call([ 'apt-get', 'update','--fix-missing','-y'], stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))
        try:
            subprocess.check_call([ 'apt-get', 'upgrade', '-y'], stdout=devnull, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            Errors.append(str(e))
    return Errors
    

def deny_terminal_access_to_all_users():
    passwd_file = '/etc/passwd'
    passwd_backup_file = '/etc/passwd.backup'

    # Check if the backup file exists, if not, create it
    if not os.path.exists(passwd_backup_file):
        with open(passwd_file, 'r') as src, open(passwd_backup_file, 'w') as dst:
            dst.writelines(src.readlines())

    # Read the contents of /etc/passwd
    with open(passwd_file, 'r') as f:
        lines = f.readlines()

    # Modify the shell entry for each user to /bin/false if it's not already set
    modified = False
    for i, line in enumerate(lines):
        parts = line.strip().split(':')
        if parts[-1] != '/bin/false':
            parts[-1] = '/bin/false'  # Change the shell to /bin/false
            lines[i] = ':'.join(parts) + '\\n'
            modified = True

    # Write the modified contents back to /etc/passwd only if changes were made
    if modified:
        with open(passwd_file, 'w') as f:
            f.writelines(lines)

        print('{}Terminal Access:{} Denied for all users. {}#SuckItBob{}'.format(Color.YELLOW,Color.RED,Color.CYAN,Color.END))
    else:
        print('No changes needed. All users already have terminal access denied.')
def get_specific_input(data_type, custom_text):
    while True:
        try:
            user_input = raw_input(custom_text)
            data=data_type(user_input)
            return data
        except ValueError:
            print('Please enter a valid {}\!'.format(data_type.__name__))
def expand_ip_range(short_ip_range):
    parts = short_ip_range.split('.')
    expanded_parts = []

    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            expanded_part = (start, end)
        else:
            expanded_part = (int(part), int(part))
        expanded_parts.append(expanded_part)

    return expanded_parts
def password_reset():
    passwd_output = subprocess.check_output(['cut', '-d:', '-f1', '/etc/passwd'])
    users = passwd_output.split('\\n')
    users.remove('')
    for account in users:
        new_password = random.choice(Passwords) + '_' + ''.join(random.choice(characters) for _ in range(6))
        errormessage = subprocess.Popen(['passwd', account], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, universal_newlines=True).communicate(
            input=new_password + '\\n' + new_password + '\\n')
        print('''User: {}{}{} \\n>>Password: {}{}{}''').format(Color.YELLOW, account, Color.END, Color.YELLOW,
                                                               new_password, Color.END)
def bool_check(given):
    return bool('true'==str(given))
def string_to_number_list(string_numbers):
    return [int(x) for x in string_numbers.split(',')]
def config_firewall(MyIP,DefaultGateway,Username):
    # Clear Current Rules
    subprocess.call(['iptables', '-F'])  # Flush existing rules
    #Preserve ME
    subprocess.call('iptables -A INPUT -s {} -j ACCEPT'.format(MyIP), shell=True)
    subprocess.call('iptables -A OUTPUT -d {} -j ACCEPT'.format(MyIP), shell=True)
    print('{}Configure Firewall: {}Preserved Access of {}{}{}'.format(Color.YELLOW,Color.END,Color.GREEN,Username,Color.END))
    subprocess.call(['iptables', '-P', 'INPUT', 'DROP'])
    subprocess.call(['iptables', '-P', 'FORWARD', 'DROP'])
    subprocess.call(['iptables', '-P', 'OUTPUT', 'DROP'])
    print('{}Configure Firewall: {}Default IN-OUT set to Drop{}'.format(Color.YELLOW,Color.RED,Color.END))
    DGports=get_specific_input(string_to_number_list,'{}Configure Firewall: {}Ports to allow from the default gateway. (Seperate with ,):'.format(Color.YELLOW,Color.END))
    for Port in DGports:
        subprocess.call('iptables -A INPUT -p tcp -s {} --dport {} -j ACCEPT'.format(DefaultGateway,Port), shell=True)
        subprocess.call('iptables -A OUTPUT -p tcp -d {} --dport {} -j ACCEPT'.format(DefaultGateway,Port), shell=True)
    print(('{}Default Gateway Allowed{}: {}'+', '.join(map(str, DGports))+'{}').format(Color.YELLOW,Color.END,Color.RED,Color.END))
    # Install iptables-persistent and wait for it to finish
    print('{}Installing{} IPTables-persistant{} to function as {}Sys-Firewall{}'.format(Color.YELLOW,Color.PURPLE,Color.END,Color.GREEN,Color.END))
    #I'll make my own directories suck it bob
    backup_dir = '/etc/iptables/'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    #backup Existing Config
    with open('/etc/iptables/rules.v4.backup', 'w') as backup_file:
        subprocess.Popen(['iptables-save'], stdout=backup_file)

    print('{}Configure Firewall: {} Allowed Ports{} and {}Ip\'s{} that can connect to them:'.format(Color.YELLOW,Color.PURPLE,Color.END,Color.RED,Color.END))
    while True:
        Port=get_specific_input(int,'{}Port:{} Enter Port # or {}0{} when done:'.format(Color.YELLOW,Color.END,Color.RED,Color.END))
        if(0 == Port):
            break
        UserIpInput=get_specific_input(str,'{}Port:{} {}{}{} Please enter Ips (Seperate with,):'.format(Color.YELLOW,Color.END,Color.RED,Port,Color.END))
        IPaddress=UserIpInput.split(',')
        if('all' in UserIpInput.lower()):
            subprocess.call('iptables -A INPUT -p tcp --dport {} -j ACCEPT'.format(Port), shell=True)
            subprocess.call('iptables -A OUTPUT -p tcp --dport {} -j ACCEPT'.format(Port), shell=True)  
        elif(all(len(item.split('.')) == 4 for item in IPaddress)):
            ConfiguredIps='{}Configured Allowed Ips on Port {}{}{}:'.format(Color.YELLOW,Color.GREEN,Port,Color.CYAN)
            for IPaddress in IPaddress:
                MinMaxIP=expand_ip_range(IPaddress)
                MinIP=str(MinMaxIP[0][0])+'.'+str(MinMaxIP[1][0])+'.'+str(MinMaxIP[2][0])+'.'+str(MinMaxIP[3][0])
                MaxIP=str(MinMaxIP[0][1])+'.'+str(MinMaxIP[1][1])+'.'+str(MinMaxIP[2][1])+'.'+str(MinMaxIP[3][1])
                subprocess.call('iptables -A INPUT -p tcp --dport {} -m iprange --src-range {} -j ACCEPT'.format(Port,MinIP+'-'+MaxIP), shell=True)
                subprocess.call('iptables -A OUTPUT -p tcp --sport {} -m iprange --src-range {} -j ACCEPT'.format(Port,MinIP+'-'+MaxIP), shell=True)
                ConfiguredIps+='\\n'+MinIP+'-'+MaxIP
            print(Color.END+ConfiguredIps)
        else:
            print('{}Configure Firewall:{} YO DUMASS, use a valid format next time:{}X.X.X.X,X.x-X.x-X.x-X{}'.format(Color.YELLOW,Color.END,Color.RED,Color.END))
    print('Firewall rules configured successfully.')
    
def disable_ipv6():
    # Backup current IPv6 rules
    subprocess.call('ip6tables-save > /etc/iptables/rules.v6.backup', shell=True)

    # Set default policies
    subprocess.call('ip6tables -P INPUT DROP', shell=True)
    subprocess.call('ip6tables -P FORWARD DROP', shell=True)
    subprocess.call('ip6tables -P OUTPUT DROP', shell=True)

    # Save the updated rules
    subprocess.call('ip6tables-save > /etc/iptables/rules.v6', shell=True)

def lockdown_shadow_and_root():
    for command in FileLockDownCommands:
        subprocess.Popen(command, shell=True)
def backup_config(file_path):
    subprocess.Popen(['cp', file_path, file_path + '.backup'])

def create_ssh_banner(message, banner_path):
    with open(banner_path, 'w') as f:
        f.write(message)
    print('{}SSHd Config:{} Banner created at: {}'.format(Color.YELLOW,Color.END,banner_path))

def update_ssh_config(banner_path, allowed_user):
    sshd_config_path = '/etc/ssh/sshd_config'
    sshd_config_backup_path = '/etc/ssh/sshd_config.backup'

    try:
        # Backup the original sshd_config file
        os.rename(sshd_config_path, sshd_config_backup_path)

        # Read the entire content of the original sshd_config file
        with open(sshd_config_backup_path, 'r') as f_in:
            config_content = f_in.read()

        # Check if AllowUsers already exists in the configuration
        allow_users_match = re.search(r'^\s*#?\s*AllowUsers.*$', config_content, flags=re.MULTILINE)
        
        if allow_users_match:
            # If AllowUsers exists, modify it
            config_content = re.sub(allow_users_match.group(), 'AllowUsers {}'.format(allowed_user), config_content)
        else:
            # If AllowUsers does not exist, add it to the configuration
            config_content += '\\nAllowUsers {}\\n'.format(allowed_user)

        # Replace or add Banner configuration
        config_content = re.sub(r'^\s*#?\s*Banner.*$', 'Banner {}'.format(banner_path), config_content, flags=re.MULTILINE)

        # Write the modified content back to the sshd_config file
        with open(sshd_config_path, 'w') as f_out:
            f_out.write(config_content)

        # Change ownership and permissions
        #subprocess.call(['chown', 'root:root', sshd_config_path])
        #subprocess.call(['chmod', '600', sshd_config_path])
        
        # Restart SSH service
        subprocess.call([ 'systemctl', 'restart', 'ssh'])

    except Exception as e:
        # Restore original sshd_config in case of error
        os.rename(sshd_config_backup_path, sshd_config_path)
        print('An error occurred: {}'.format(e))

if __name__ == '__main__':
    main()
