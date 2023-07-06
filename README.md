# My-Dropbox

UC Berkeley CS161 - "Computer Security" Project

Language: Golang
Libraries/Packages: "github.com/cs161-staff/project2-userlib"- for server handling and trsting features, "github.com/google/uuid" - The uuid package generates and inspects UUIDs, encoding/json, strings, fmt, erros, stringconv

In this project, I implemented a client for a file stroring and sharing system. The client will allow users to store and load files,
share files with other users, and revoke access to a shared file from other users. Users of this application will launch the client and provide their username and password. Once authenticated, they will use the client to upload and download files to/from the server. 

We provided two servers: 
  Keystore, provides a public key store for everyone. It is trusted. 
  Datastore, provides key-value storage for everyone. It is untrusted.
  
Using cryptographic security algorithms such as symmetric/asymmetric encryption, MACs, and Digital Signatures and the provided servers, I implemented the following functions: 

InitUser: Initializing a user and their public/private keys for file storage and sharing
GetUser: Retrieving the above data
StoreFile: Using the provided keys of an user, encrypting, and storing the data into the untrusted server
AppendFile: Adding blocks of data/information to already stored data
LoadFile: Retrieving entire data files from the unstrusted server
ShareFile: Sending an invitation/file information to another user over untrusted server  
ReceiveFile: accepting that invitation to gain access over untrusted server  
RevokeFile: Removing file access of specific users without changing the status of other users

In addition, I provided tests to ensure the functionality of the program as well as the robustness of the security accounting for all malicious activities to access files. 
