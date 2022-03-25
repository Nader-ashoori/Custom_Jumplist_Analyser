import os
import tabloo
import pandas as pd
import time
from colorama import Fore,Back,Style
from colorama import init
import re
import subprocess
from mac_vendor_lookup import MacLookup


init(convert=True)
lib_directory = (tabloo.__file__)
lib_dir_search  = (re.search(".*tabloo", lib_directory))
lib_dir_output =  (lib_dir_search.group())
lib_dir_create = (lib_dir_output + "\static\styles.css")
Replace_css = subprocess.check_output("copy /Y .\\styles.css " + lib_dir_create, shell=True )

def Mac_check(dir):
    df = pd.read_csv(dir)
    ab1 = df[df['MachineMACAddress'].notnull()]
    selection = ab1['MachineMACAddress'].unique()
    for i in selection:
        try:
            print(i+ '   ===>  ' +MacLookup().lookup(i))
        except KeyError as error:
            print (i + '   ===> ' +" Mac address Not Detect")

def time_checker():
    time_now = time.strftime("%Y%m%d-%H%M%S")
    return time_now
def tableshow_suspicuos(directory):
    df = pd.read_csv(directory)
    df = df.drop(['FileSize','SourceFile','SourceModified','AppId','EntryName','TargetModified','TargetAccessed','RelativePath','WorkingDirectory','FileAttributes',
    'HeaderFlags','DriveType','VolumeSerialNumber','VolumeLabel','CommonPath','TargetMFTEntryNumber','TargetMFTSequenceNumber','TrackerCreatedOn','ExtraBlocksPresent'], axis=1)
    df =  (df[df['MachineMACAddress'].notnull()])
    df = (df[df['Arguments'].astype(str).str.contains('cmd') | df['Arguments'].astype(str).str.contains('powershell')| df['Arguments'].astype(str).str.contains('\.ps1')
    | df['Arguments'].astype(str).str.contains('\.bat')| df['Arguments'].astype(str).str.contains('\.hta')| df['Arguments'].astype(str).str.contains('\.py') 
    |df['Arguments'].astype(str).str.contains('\.exe') |df['Arguments'].astype(str).str.contains('\.js')  ])
   
    tabloo.show(df)
    return
def listdir_check(input1):
    return  os.listdir(input1)

def Tableshow_connection(directory):
    df = pd.read_csv(directory)
    df = df.drop(['FileSize','SourceFile','SourceModified','AppId','EntryName','TargetModified','TargetAccessed','RelativePath','WorkingDirectory','FileAttributes',
    'HeaderFlags','DriveType','VolumeSerialNumber','VolumeLabel','CommonPath','TargetMFTEntryNumber','TargetMFTSequenceNumber','TrackerCreatedOn','ExtraBlocksPresent'], axis=1)
    df =  (df[df['MachineMACAddress'].notnull()])
    df = (df[df['Arguments'].astype(str).str.contains('http') | df['Arguments'].astype(str).str.contains('file')])
 
    tabloo.show(df)
    return
while True:
    try:
        Drive_letter = input("Please Enter Drive Letter to Extract Jumplist:")
        Users_list = os.listdir("%s:\\Users" %Drive_letter)
        break
    except FileNotFoundError as error:
        print (Fore.RED +"Please Checking again Drive Letter!"+ Fore.RESET)

Counter_user = len(Users_list)

for i in range(1,Counter_user): 
    print (Fore.BLUE + str(i)+")"+ Users_list[i] + Fore.RESET)

print (Fore.GREEN + str(Counter_user)+")all user" + Fore.RESET)

User_selection=input("Choose Your Number of user:")
files_detect =[]

if int(User_selection) == int(Counter_user):
    print (Fore.BLUE +"Please wait to Extract Custom Jumplist via JLEcmd ..."+ Fore.RESET)
    for rolles in Users_list:
        all_user_command = subprocess.check_output('.\\JLECmd.exe -d %s:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations --csv .\\Export\\%s' %(Drive_letter,rolles,rolles), shell=True)
    print ("\n\n===============================================================================\n\nDone Extract!\n")
    for users in listdir_check(".\\Export\\"):
        jumplist_user_selection = listdir_check(".\\Export\\%s\\"%users)
        csv_get = listdir_check('.\\Export\\%s'%(users))
        df = pd.read_csv('.\\Export\\%s\\%s'%(users,csv_get[0]))
        df['User'] = users
        df.to_csv('.\\Export\\%s\\%s'%(users,csv_get[0]))
        files_detect.append('.\\Export\\%s\\%s' %(users,csv_get[0]))
    counter_detect = 0
    file_name = []
    for i in (files_detect):
        file_name.append('files_reader'+str(counter_detect))
        file_name[counter_detect] = pd.read_csv(files_detect[counter_detect])
        counter_detect += 1
    concat_table =pd.concat(file_name)
    os.system("mkdir .\\Export\\ReportFile")
    file_name_report = ("Report_concat_"+time_checker()+".csv")
    concat_table.to_csv('.\\Export\\ReportFile\\%s' %file_name_report , index=False, quoting=1)
    print ( Fore.RED +"Mac Address Refrences to analysis :"+ Fore.RESET)
    Mac_check('.\\Export\\ReportFile\\%s' %file_name_report)
    print ('\n\n'+"---------------Show Suspicious Detected in jump list--------------------------------\n\n")
    print( Fore.BLUE + "After Watch the table Press Ctrl+C to go to the next table :" + Fore.RESET)
    tableshow_suspicuos('.\\Export\\ReportFile\\%s' %file_name_report)
    print ("---------------Show Connections Detected in jump list--------------------------------")
    Tableshow_connection('.\\Export\\ReportFile\\%s' %file_name_report)

else:
    input_command = Users_list[int(User_selection)]
    LECMD_command = os.system('.\\JLECmd.exe -d C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations --csv .\\Export\\%s' %(input_command,input_command))
    print ("\n\n===============================================================================\n\n" )
    print (Fore.RED + Style.DIM +"Done Extract!\n User %s Extracted Evidence\n" %input_command + Fore.RESET)
    jumplist_user_selection = listdir_check(".\\Export\\%s\\"%input_command)
    csv_get = listdir_check('.\\Export\\%s'%(input_command))
    print ( Fore.RED +"Mac Address Refrences to analysis :"+ Fore.RESET)
    Mac_check(csv_get)
    print ("---------------Show Connections Detected in jump list--------------------------------")
    print( Fore.BLUE + "After Watch the table Press Ctrl+C to go to the next table :" + Fore.RESET)
    Tableshow_connection('.\\Export\\%s\\%s' %(input_command,csv_get[0]))
    print ("---------------Show Suspicious Detected in jump list--------------------------------\n\n")
    tableshow_suspicuos('.\\Export\\%s\\%s' %(input_command,csv_get[0]))

 
