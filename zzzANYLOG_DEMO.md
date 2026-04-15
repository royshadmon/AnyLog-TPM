
# STEP 1: tpm instance setup
Clone this repository (in the branch fulltest)

to setup one tpm instance run the following commands:
```
./multiple-instances/setup-multiple-instances.sh 1 
docker compose -f multiple-instances/docker-compose.instances.yaml up -d
```

to reset the tpm instance run the following command:
```
./multiple-instances/manage-instances.sh reset
```

running the setup commands will create a folder in the multiple-instances folder with the name shared_dir_node1
```
multiple-instances/shared_dir_node1/
├── tpm_state/
├── key_backups/
└── signing_keys_metadata.json
```
This contains the tpm instance state and the keys for the tpm instance.



# STEP 2: env configs
Make sure to add the following at the end of the node_configs.env file:
```
#===tpm===
ENABLE_TPM=true
TPM_IP = 192.168.0.140
TPM_PORT=8001
TPM_HOST_PORT=8011
TPM_DIR="/Users/pranav/Desktop/Anylog/anylog-newthing/anylog-swtpm/SWTPM-FastAPI/multiple-instances/shared_dir_node1"
# replace TPM_DIR with the path to the folder created in the multiple-instances folder
```

can refer to my docker-compose branch (pp-dev2) as a reference for the env configs.

# STEP 3: deployment setup
Add the following to the main.al in the deployment scripts right after localscripts and test_dir are set:

```
if $TPM_DIR then set tpm_dir = $TPM_DIR
if $TPM_IP then set tpm_ip = $TPM_IP
if $TPM_PORT then set tpm_port = $TPM_PORT
# is_tpm = file test !tpm_dir
# if not !is_tpm then error to show no tpm and decide if program wants to coninue/not continue

tpm_base_url = !tpm_ip + : + !tpm_port
tpm set where conn = !tpm_base_url and tpm_dir = !tpm_dir
```


# STEP 4: tpm commands to run and test

Below is a testing script used to run tpm commands and test the tpm instance. The setup needed is one master and one operator. The url for the isntance is your inet/en0 ip and the port is 8001. 


## ON OP 1

```
root_key_file = root_key
id create keys where password = 123 and keys_file = !root_key_file


<member = {"member" : {  
    "type" : "root",  
    "name"  : "rachel"  
    }  
}>

id sign !member where key = !root_key_file and password = 123

json !member

blockchain insert where policy = !member and local = true and master = !ledger_conn

id create keys for node where password = abc

<member = {"member" : {
    "id"   : "node_001",
    "type" : "node",
    "company"  : "Northern Light",
    "name" : "server south"
    }
}>

id sign !member where key = node and password = abc

json !member

blockchain insert where policy = !member and local = true and master = !ledger_conn


<permissions = {"permissions" : {
    "name" : "node basic permissions",
    "databases" : ["*", "-lsl_demo"],
    "tables" : ["lsl_demo.temperature_sensor", "lsl_demo.ping_sensor"],
    "enable" : [ "file", "get", "reset", "sql", "echo", "print", "blockchain"],
    "disable" : ["get node id"]
    }
}>

id sign !permissions where key = !root_key_file and password = 123

json !permissions

blockchain insert where policy = !permissions and local = true  and master = !ledger_conn 


member_node1 = blockchain get member where id = node_001 bring ['member']['public_key']

permission_id =  blockchain get permissions where name = "node basic permissions" bring ['permissions']['id']

<assignment = {"assignment" : {
        "permissions"  : !permission_id,
        "members"  : [!member_node1]
        }
}>

id sign !assignment where key = !root_key_file and password = 123

json !assignment 

blockchain insert where policy = !assignment and local = true  and master = !ledger_conn  
```
## ON MASTER
```
tpm_dir = /Users/roy/Github-Repos/AnyLog-TPM/multiple-instances/tpm_shared_dir2
tpm_port = 8002
tpm_ip = $INET_IP
tpm_base_url = !tpm_ip + : + !tpm_port
root_key_file = root_key
tpm set where conn = !tpm_base_url and tpm_dir = !tpm_dir


id create keys for node where password = xyz

<member = {"member" : {  
    "type" : "node",  
    "name"  : "master_node"  
    }  
}>  

id sign !member where key = node and password = xyz

json !member

blockchain insert where policy = !member and local = true and master = !ledger_conn
```
## ON OP 1
```
<permissions = {"permissions" : {
    "name" : "master node permissions",
    "enable" : [ "file", "get status", "event", "echo", "print"]
    }
}>

id sign !permissions where key = !root_key_file and password = 123

json !permissions

blockchain insert where policy = !permissions and local = true  and master = !ledger_conn 


permission_id = blockchain get permissions where name = "master node permissions" bring ['permissions']['id']
member_node = blockchain get member where name = master_node bring ['member']['public_key']

<assignment = {"assignment" : {
        "name" : "master assignment",
        "permissions"  : !permission_id,
        "members"  : [!member_node]
        }
}>

id sign !assignment where key = !root_key_file and password = 123

json !assignment 

blockchain insert where policy = !assignment and local = true  and master = !ledger_conn  

```
## ON ALL 
```
tpm set where conn = 192.168.86.31:8001

tpm enabled = on

tpm get info

set node authentication on
```

## TESTING

test by doing commands like run client ([ip:port]) get status or echo hello to see if the nodes are connected and working.
