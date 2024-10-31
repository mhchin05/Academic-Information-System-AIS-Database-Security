-- ====================== Set Up Transparent Data Encryption (TDE) ======================
USE master;
GO
-- 1. Create a master key to protect the certificate 
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword@123';
GO

-- 2. Create a certificate to protect the database encryption key (DEK)
CREATE CERTIFICATE MyTDECertificate
WITH SUBJECT = 'TDE Certificate for Database Encryption';
GO

-- 3. Create the database encryption key (DEK) and protect it with the certificate
USE AIS;  
GO
-- This encryption key will be used to encrypt the entire database using the AES_256 algorithm
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE MyTDECertificate;
GO

-- 4. Enable Transparent Data Encryption (TDE) on the database
ALTER DATABASE AIS
SET ENCRYPTION ON;
GO

-- 5. Backup the TDE Database
-- Perform a full backup of the TDE-encrypted database
BACKUP DATABASE AIS  
TO DISK = 'C:\Backup\AIS_TDE.bak'
WITH FORMAT;
GO

-- 6. Backup the TDE certificate and private key
-- The TDE certificate and private key must be backed up to restore the database on another server
USE master
GO
BACKUP CERTIFICATE MyTDECertificate 
TO FILE = 'C:\Backup\MyTDECertificate.cer'
WITH PRIVATE KEY (FILE = 'C:\Backup\MyTDECertificate_PrivateKey.key', 
    ENCRYPTION BY PASSWORD = 'StrongerPassword!@#$1234');
GO

-- ==================================== Database Creation ====================================
-- Create the Academic Information System (AIS) database --
Create Database AIS;
GO

-- ==================================== Table Creation ====================================
-- Switch to the AIS database --
Use AIS;
GO

-- Create the Student Table to store relevant student attributes --
Create Table Student(
    ID varchar(6) primary key,              -- Student ID (Primary Key)
    SystemPwd varbinary(max),               -- Encrypted Password for the Student
    Name varchar(100) not null,             -- Student's Full Name
    Phone varchar(20)                       -- Student's Phone Number
);
GO

-- Create the Lecturer Table to store relevant lecturer attributes --
Create Table Lecturer(
    ID varbinary(256) primary key,          -- Encrypted Lecturer ID (Primary Key)
    SystemPwd varbinary(max),               -- Encrypted Password for the Lecturer
    Name varchar(100) not null,             -- Lecturer's Full Name
    Phone varchar(20),                      -- Lecturer's Phone Number
    Department varchar(30)                  -- Lecturer's Department
);
GO

-- Create the Subject Table to store subject information --
Create Table Subject(
    Code varchar(5) primary key,            -- Subject Code (Primary Key)
    Title varchar(30)                       -- Subject Title
);
GO

-- Create the Result Table to store students' results --
Create Table Result(
    ID int primary key identity (1,1),      -- Auto-incremented Result ID (Primary Key)
    StudentID varchar(6) references Student(ID),  -- Foreign Key referencing Student Table
    LecturerID varbinary(256) references Lecturer(ID),  -- Foreign Key referencing Lecturer Table
    SubjectCode varchar(5) references Subject(Code),    -- Foreign Key referencing Subject Table
    AssessmentDate date,                    -- Date of Assessment
    Grade varchar(2)                        -- Grade of the Student
);
GO

-- Create the AuditLog Table to store DML, LOGIN, DDL, and DCL audit logs --
CREATE TABLE dbo.AuditLog (
    AuditID INT IDENTITY(1,1) PRIMARY KEY,  -- Auto-incremented Audit ID (Primary Key)
    EventTime DATETIME,                     -- Event Timestamp
    ActionID NVARCHAR(50),                  -- Action ID (e.g., LGIS, LGIF for logins)
    Succeeded BIT,                          -- Whether the action succeeded or failed
    SessionID INT,                          -- Session ID for the event
    ServerPrincipalName NVARCHAR(100),      -- Server-level principal (user performing the action)
    DatabasePrincipalName NVARCHAR(100),    -- Database-level principal (optional)
    ObjectName NVARCHAR(100),               -- Affected object (e.g., table name)
    Statement NVARCHAR(MAX),                -- Executed SQL statement
    AdditionalInfo NVARCHAR(MAX),           -- Any additional information related to the action
    LogType NVARCHAR(10)                    -- Log type (e.g., DML, LOGIN, DDL, DCL)
);
GO

--==================================== User Creation ====================================
USE master;
GO
-- Authentication
-- Create SQL logins (server-level logins) --
CREATE LOGIN A001 WITH PASSWORD = 'Admin123';    -- Admin Login 1
CREATE LOGIN A002 WITH PASSWORD = 'Admin456';    -- Admin Login 2
CREATE LOGIN L001 WITH PASSWORD = 'Lecturer123'; -- Lecturer Login 1
CREATE LOGIN L002 WITH PASSWORD = 'Lecturer456'; -- Lecturer Login 2
CREATE LOGIN S001 WITH PASSWORD = 'Student123';  -- Student Login 1
CREATE LOGIN S002 WITH PASSWORD = 'Student456';  -- Student Login 2


USE AIS;
GO
-- Authorization
-- Create roles for database-level access control --
CREATE ROLE DataAdmin;       -- Role for Data Administrators
CREATE ROLE Lecturer;        -- Role for Lecturers
CREATE ROLE Student;         -- Role for Students
GO

-- Create Database Users mapped to the previously created logins --
CREATE USER A001 FOR LOGIN A001;
CREATE USER A002 FOR LOGIN A002;
CREATE USER L001 FOR LOGIN L001;
CREATE USER L002 FOR LOGIN L002;
CREATE USER S001 FOR LOGIN S001;
CREATE USER S002 FOR LOGIN S002;

-- Add Users to their respective Roles --
ALTER ROLE DataAdmin ADD MEMBER A001;
ALTER ROLE DataAdmin ADD MEMBER A002;
ALTER ROLE Lecturer ADD MEMBER L001;
ALTER ROLE Lecturer ADD MEMBER L002;
ALTER ROLE Student ADD MEMBER S001;
ALTER ROLE Student ADD MEMBER S002;



-- ===================== Database Key Creation and Security Setup ======================
USE AIS;
GO
-- Create a master key to protect the asymmetric key (for password encryption)
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongMasterKeyPassword@123';
GO

-- Create the asymmetric key using RSA 2048 for password encryption
CREATE ASYMMETRIC KEY MyRSAKey
WITH ALGORITHM = RSA_2048;
GO

-- Create the symmetric key for Lecturer ID encryption (AES-256)
CREATE SYMMETRIC KEY LecturerIDKey
WITH ALGORITHM = AES_256
ENCRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO

-- ============================Apply Data Masking ====================================
-- Apply partial masking to the Phone column in Lecturer table
ALTER TABLE Lecturer
ALTER COLUMN Phone VARCHAR(20) MASKED WITH (FUNCTION = 'partial(0,"XXX-XXX",4)');
GO

-- Apply partial masking to the Phone column in Student table
ALTER TABLE Student
ALTER COLUMN Phone VARCHAR(20) MASKED WITH (FUNCTION = 'partial(0,"XXX-XXX",4)');
GO

-- Apply default masking to the Grade column in the Result table
ALTER TABLE Result
ALTER COLUMN Grade VARCHAR(2) MASKED WITH (FUNCTION = 'default()');
GO


--==================================== Audit Log  ====================================
------------------------------------------------------------------------------------------------------------------
--                       1) SQL Server Audit For Login
-- Track successful and failed logins, password changes, successful logouts (exit SSMS)
------------------------------------------------------------------------------------------------------------------
USE master;
GO

-- Create the audit for tracking User Logins
CREATE SERVER AUDIT [Login_Audit]
TO FILE (FILEPATH = 'C:\Audit_Logs\Logins')
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO


-- Create an audit specification for logins (successful and failed), password changes, and successful logouts
CREATE SERVER AUDIT SPECIFICATION [Login_Audit_Spec]  
FOR SERVER AUDIT [Login_Audit]
ADD (SUCCESSFUL_LOGIN_GROUP),		-- Track successful logins
ADD (FAILED_LOGIN_GROUP),			-- Track failed logins
ADD (LOGIN_CHANGE_PASSWORD_GROUP),  -- Track password changes
ADD (LOGOUT_GROUP);					-- Track successful logouts
GO


-- Start the audit & audit specification
ALTER SERVER AUDIT [Login_Audit] WITH (STATE = ON);
ALTER SERVER AUDIT SPECIFICATION [Login_Audit_Spec] WITH (STATE = ON);
GO


-- Check if the audit is enabled
SELECT name, is_state_enabled
FROM sys.server_audits;



-- Query the audit log directly
SELECT event_time, 
       action_id, 
       succeeded, 
       session_id, 
       server_principal_name, 
       database_principal_name, 
       statement, 
       additional_information
FROM sys.fn_get_audit_file('C:\Audit_Logs\Logins\*.sqlaudit', DEFAULT, DEFAULT);

/**
	LGIS for successful logins.
	LGIF for failed logins.
	PWC for password changes.
	LOGG for logouts.
	AUSC for tracking starting, stopping, enabling, or disabling server audits
**/


------------------------------------------------------------------------------------------------------------------
--                      2) Database structural changes (DDL Audit)
-- changes made by database query executions, such as database & table creation and deletion
------------------------------------------------------------------------------------------------------------------
USE master ;  
GO  

-- Create the audit for tracking DDL Activities
CREATE SERVER AUDIT [DDL_Audit]
TO FILE (FILEPATH = 'C:\Audit_Logs\DDL')
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO


CREATE SERVER AUDIT SPECIFICATION [DDL_Audit_Spec]
FOR SERVER AUDIT [DDL_Audit]
ADD (DATABASE_OBJECT_CHANGE_GROUP),			-- Tracks DDL changes at the object level (CREATE, ALTER, DROP on tables, views, etc.)
ADD (DATABASE_CHANGE_GROUP),				-- Tracks changes at the database level (CREATE, ALTER, DROP on the database itself)
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP);    -- Tracks role creation and changes within a database !!!!!!!!!!!!!!!!!!!!!!!!!!!!!! GOT PROBLEM
GO

-- Start the audit & audit specification
ALTER SERVER AUDIT [DDL_Audit] WITH (STATE = ON);
ALTER SERVER AUDIT SPECIFICATION [DDL_Audit_Spec] WITH (STATE = ON);
GO


-- Query the audit log to see the captured DDL activities
SELECT event_time, 
       action_id, 
       succeeded, 
       session_id, 
       server_principal_name, 
       database_principal_name, 
       statement, 
       additional_information
FROM sys.fn_get_audit_file('C:\Audit_Logs\DDL\*.sqlaudit', DEFAULT, DEFAULT);  -- Adjust file path as necessary
GO



------------------------------------------------------------------------------------------------------------------
--                    3) Data access (DQL) and manipulations (DML Audit)
-- changes made on data such as data being viewed, added, updated or deleted
------------------------------------------------------------------------------------------------------------------
USE master ;  
GO  

-- Create the audit for tracking DML activities
CREATE SERVER AUDIT [DML_Audit]
TO FILE (FILEPATH = 'C:\Audit_Logs\DML')
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO


-- Create the server audit specification for tracking DQL (data access) and DML (data manipulation)
CREATE SERVER AUDIT SPECIFICATION [DML_Audit_Spec]
FOR SERVER AUDIT [DML_Audit]
ADD (SCHEMA_OBJECT_ACCESS_GROUP), -- Captures SELECT (data access)
ADD (SCHEMA_OBJECT_CHANGE_GROUP); -- Captures DML (data manipulations like INSERT, UPDATE, DELETE)
GO


-- Start the audit and audit specification
ALTER SERVER AUDIT [DML_Audit] WITH (STATE = ON);
ALTER SERVER AUDIT SPECIFICATION [DML_Audit_Spec] WITH (STATE = ON);

GO


-- Query the DML audit log to see all the data manipulations
SELECT event_time,
       action_id,
       session_id,
       server_principal_name,
       database_principal_name,
       object_name,
       statement,
       succeeded
FROM sys.fn_get_audit_file('C:\Audit_Logs\DML\*.sqlaudit', DEFAULT, DEFAULT)
WHERE object_name IN ('Student', 'Lecturer', 'Subject', 'Result')
  AND statement IN ('INSERT', 'PREPARED QUERY', 'DELETE', 'SELECT');
GO



------------------------------------------------------------------------------------------------------------------
--                    4) Database permission changes (DCL Audit) 
-- changes made to users permissions (Grant, Deny and Revoke operations can affect user access)
------------------------------------------------------------------------------------------------------------------

-- Create the audit for tracking permission changes
CREATE SERVER AUDIT [DCL_Audit]
TO FILE (FILEPATH = 'C:\Audit_Logs\DCL')
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO


-- Create the server audit specification for tracking permission changes
CREATE SERVER AUDIT SPECIFICATION [DCL_Audit_Spec]
FOR SERVER AUDIT [DCL_Audit]
ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP), -- Tracks permission changes on database objects (GRANT, REVOKE, DENY)
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP),   -- Tracks permission changes at the server level
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP);  
GO

-- Start the audit and audit specification
ALTER SERVER AUDIT [DCL_Audit] WITH (STATE = ON);
ALTER SERVER AUDIT SPECIFICATION [DCL_Audit_Spec] WITH (STATE = ON);
GO


-- For DCL logs
SELECT event_time, 
       action_id, 
       session_id, 
       server_principal_name, 
       database_principal_name, 
       object_name, 
       statement, 
       succeeded
FROM sys.fn_get_audit_file('C:\Audit_Logs\DCL\*.sqlaudit', DEFAULT, DEFAULT); -- For DCL logs
GO



------------------------------------- USE PROCEDURE TO FETCH LOGS INTO AUDIT TABLE -------------------------------
-- Procedure to fetch filtered DML logs and insert into the custom audit table
CREATE OR ALTER PROCEDURE sp_InsertDMLAudit
AS
BEGIN
    INSERT INTO dbo.AuditLog (EventTime, ActionID, Succeeded, SessionID, ServerPrincipalName, DatabasePrincipalName, ObjectName, Statement, AdditionalInfo, LogType)
    SELECT 
        event_time, 
        action_id, 
        succeeded, 
        session_id, 
        server_principal_name, 
        database_principal_name, 
        object_name, 
        statement, 
        NULL AS AdditionalInfo,
        'DML' AS LogType
    FROM sys.fn_get_audit_file('C:\Audit_Logs\DML\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE object_name IN ('Student', 'Lecturer', 'Subject', 'Result')  -- Filter for specific tables
      AND statement IN ('INSERT', 'PREPARED QUERY', 'DELETE', 'SELECT');  -- Filter for specific statements
END;
GO

USE AIS
GO
DROP PROCEDURE sp_InsertDMLAudit

USE AIS;
GO

-- Procedure to fetch LOGIN logs and insert into the custom audit table
CREATE OR ALTER PROCEDURE sp_InsertLoginAudit
AS
BEGIN
    INSERT INTO dbo.AuditLog (EventTime, ActionID, Succeeded, SessionID, ServerPrincipalName, DatabasePrincipalName, ObjectName, Statement, AdditionalInfo, LogType)
    SELECT 
        event_time, 
        action_id, 
        succeeded, 
        session_id, 
        server_principal_name, 
        NULL AS DatabasePrincipalName, 
        NULL AS ObjectName, 
        statement, 
        additional_information,
        'LOGIN' AS LogType
    FROM sys.fn_get_audit_file('C:\Audit_Logs\Logins\*.sqlaudit', DEFAULT, DEFAULT);
END;
GO

USE AIS;
GO

-- Procedure to fetch DDL logs and insert into the custom audit table
CREATE OR ALTER PROCEDURE sp_InsertDDLAudit
AS
BEGIN
    INSERT INTO dbo.AuditLog (EventTime, ActionID, Succeeded, SessionID, ServerPrincipalName, DatabasePrincipalName, ObjectName, Statement, AdditionalInfo, LogType)
    SELECT 
        event_time, 
        action_id, 
        succeeded, 
        session_id, 
        server_principal_name, 
        database_principal_name, 
        NULL AS ObjectName, 
        statement, 
        additional_information,
        'DDL' AS LogType
    FROM sys.fn_get_audit_file('C:\Audit_Logs\DDL\*.sqlaudit', DEFAULT, DEFAULT);
END;
GO

USE AIS;
GO

-- Procedure to fetch DCL logs and insert into the custom audit table
CREATE OR ALTER PROCEDURE sp_InsertDCLAudit
AS
BEGIN
    INSERT INTO dbo.AuditLog (EventTime, ActionID, Succeeded, SessionID, ServerPrincipalName, DatabasePrincipalName, ObjectName, Statement, AdditionalInfo, LogType)
    SELECT 
        event_time, 
        action_id, 
        succeeded, 
        session_id, 
        server_principal_name, 
        database_principal_name, 
        object_name, 
        statement, 
        additional_information,
        'DCL' AS LogType
    FROM sys.fn_get_audit_file('C:\Audit_Logs\DCL\*.sqlaudit', DEFAULT, DEFAULT);
END;
GO

EXEC sp_InsertDMLAudit;
EXEC sp_InsertLoginAudit;
EXEC sp_InsertDDLAudit;
EXEC sp_InsertDCLAudit;

Select * from AuditLog


---------------------------------------------------------------------------------------------------------------
--								System Versioned Temporal Tables 
---------------------------------------------------------------------------------------------------------------
 
-- Step 1: Add the period columns to the Subject table
ALTER TABLE Subject
ADD 
    ValidFrom DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,
    ValidTo DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL,
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo); -- Required for temporal tables
 
-- Step 2: Enable system-versioning on the Subject table
ALTER TABLE Subject
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.SubjectHistory));
 
-- The system will now track changes, including deletions, in the SubjectHistory table.
 
--_____________________________________________________________________________________________________________
 
-- Change Result table to System Versioned Temporal Table
ALTER TABLE Result
ADD ValidFrom DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,
    ValidTo DATETIME2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL,
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo);  -- Define the period for temporal data
 
ALTER TABLE Result
SET (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.ResultHistory));  -- Enable system-versioning with a history table
 
--_____________________________________________________________________________________________________________
 

----------------------------------------------------------------------------------------------------------
-- Trigger for Logging Actions on the Result, Student, Lecturer, Subject Table
----------------------------------------------------------------------------------------------------------
 
CREATE TABLE Trg_AuditLog (
    ID INT IDENTITY PRIMARY KEY,
    ActionType NVARCHAR(50),
    TableName NVARCHAR(50),
    ChangeTime DATETIME,
    UserName NVARCHAR(100)
);
 
 
CREATE OR ALTER PROCEDURE sp_LogAuditAction
    @ActionType NVARCHAR(50),
    @TableName NVARCHAR(50)
AS
BEGIN
    INSERT INTO Trg_AuditLog (ActionType, TableName, ChangeTime, UserName)
    VALUES (@ActionType, @TableName, GETDATE(), SUSER_SNAME());
END;
GO
 
-- result table
CREATE OR ALTER TRIGGER trg_AuditResultModifications
ON Result
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    -- Capture INSERT or UPDATE actions
    IF EXISTS (SELECT * FROM INSERTED)
    BEGIN
        -- Log a general insert or update
        EXEC sp_LogAuditAction 'INSERT or UPDATE', 'Result';
    END
    ELSE
    BEGIN
        -- Log DELETE actions
        EXEC sp_LogAuditAction 'DELETE', 'Result';
    END
END;
GO
 
-- student table
CREATE OR ALTER TRIGGER trg_AuditStudentModifications
ON Student
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    IF EXISTS (SELECT * FROM INSERTED)
    BEGIN
        -- Log inserts or updates
        EXEC sp_LogAuditAction 'INSERT or UPDATE', 'Student';
    END
    ELSE
    BEGIN
        -- Log deletions
        EXEC sp_LogAuditAction 'DELETE', 'Student';
    END
END;
GO
 
-- lecturer table
CREATE OR ALTER TRIGGER trg_AuditLecturerModifications
ON Lecturer
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    IF EXISTS (SELECT * FROM INSERTED)
    BEGIN
        -- Log inserts or updates
        EXEC sp_LogAuditAction 'INSERT or UPDATE', 'Lecturer';
    END
    ELSE
    BEGIN
        -- Log deletions
        EXEC sp_LogAuditAction 'DELETE', 'Lecturer';
    END
END;
GO
 
-- subject table
CREATE OR ALTER TRIGGER trg_AuditSubjectModifications
ON Subject
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    IF EXISTS (SELECT * FROM INSERTED)
    BEGIN
        -- Log inserts or updates
        EXEC sp_LogAuditAction 'INSERT or UPDATE', 'Subject';
    END
    ELSE
    BEGIN
        -- Log deletions
        EXEC sp_LogAuditAction 'DELETE', 'Subject';
    END
END;
GO

----------------------------------------------------------------------------------------------------------
-- Trigger to Prevent Dropping Any Object
----------------------------------------------------------------------------------------------------------
 
CREATE OR ALTER TRIGGER trg_PreventDropObject
ON DATABASE
FOR DROP_TABLE, DROP_VIEW, DROP_PROCEDURE, DROP_FUNCTION, DROP_SCHEMA
AS
BEGIN
    RAISERROR('Dropping objects is not allowed.', 16, 1);
    ROLLBACK TRANSACTION;
END;
GO



-- ====================================================================================
-- ============================INSERT SOME RECORDS ====================================
-- Insert multiple student records with encrypted passwords using asymmetric encryption
INSERT INTO Student (ID, [SystemPwd], Name, Phone)
VALUES ('S001', 
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), 'Student123'),  -- Encrypt password
        'Student1',
        '014-5678901'), 
       ('S002', 
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), 'Student456'),  -- Encrypt password
        'Student2',
        '012-3456789');
GO


-- Insert multiple lecturer records with encrypted Lecturer ID and passwords
-- Open the symmetric key to use for encryption
OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO
INSERT INTO Lecturer (ID, [SystemPwd], Name, Phone, Department)
VALUES (
        ENCRYPTBYKEY(KEY_GUID('LecturerIDKey'), 'L001'),  -- Encrypt Lecturer ID
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), 'Lecturer123'),  -- Encrypt password
        'Lecturer1',
        '013-4567892',  -- Phone (masked automatically)
        'Marketing'),
       (
        ENCRYPTBYKEY(KEY_GUID('LecturerIDKey'), 'L002'),
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), 'Lecturer456'),  -- Encrypt password
        'Lecturer2',
        '012-3456789',  -- Phone (masked automatically)
        'Economics');
GO
-- Close the symmetric key after use
CLOSE SYMMETRIC KEY LecturerIDKey;
GO

---- Insert Subject Records 
INSERT INTO Subject (Code, Title)
Values('MATH1', 'Mathematics'),
	  ('ENG1', 'English');
GO


-- Insert Records into Result Table with Encrypted Lecturer ID
-- Step 1: Open the symmetric key for encryption
OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO

-- Step 2: Insert data into the Result table with correctly encrypted LecturerID
-- Ensure that the encryption of LecturerID here is consistent with the encryption in the Lecturer table
INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
VALUES 
    ('S001', (SELECT ID FROM Lecturer WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) = 'L001'), 'MATH1', '2024-07-29', 'A'),   -- Mathematics Grade for Student S001
    ('S002', (SELECT ID FROM Lecturer WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) = 'L001'), 'MATH1', '2024-09-02', 'B'),   -- Mathematics Grade for Student S002
    ('S001', (SELECT ID FROM Lecturer WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) = 'L002'), 'ENG1', '2024-07-22', 'A'),   -- English Grade for Student S001
    ('S002', (SELECT ID FROM Lecturer WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) = 'L002'), 'ENG1', '2024-07-24', 'C');   -- English Grade for Student S002
GO

-- Step 3: Close the symmetric key after inserting data
CLOSE SYMMETRIC KEY LecturerIDKey;
GO


-- ===========================================================================================================
-- Grant Control on Asymmetric Key (MyRSAKey) to Lecturer and Student
-- This grants the ability to decrypt their own passwords
-- ================================================

GRANT CONTROL ON ASYMMETRIC KEY::MyRSAKey TO Lecturer;  -- Allows Lecturer to decrypt their own password
GRANT CONTROL ON ASYMMETRIC KEY::MyRSAKey TO Student;   -- Allows Student to decrypt their own password

-- ================================================
-- Grant Permission to Open the Symmetric Key to Specific Roles
-- This allows access to decrypt sensitive data like LecturerID
-- ================================================

GRANT VIEW DEFINITION ON SYMMETRIC KEY::LecturerIDKey TO DataAdmin;  -- Allows DataAdmin to decrypt LecturerID
GRANT VIEW DEFINITION ON SYMMETRIC KEY::LecturerIDKey TO Lecturer;   -- Allows Lecturer to decrypt their own ID

-- ================================================
-- Grant UNMASK Permission at the Database Level for Masked Columns
-- Allows DataAdmin, Lecturer, and Student to view masked data
-- ================================================

-- Grant unmask permission to DataAdmin for Student and Lecturer tables (phone number)
GRANT UNMASK ON Student TO DataAdmin;   
GRANT UNMASK ON Lecturer TO DataAdmin;  

-- Grant unmask permission to Lecturer for their phone number and students' grades
GRANT UNMASK ON Result TO Lecturer;  
GRANT UNMASK ON Lecturer TO Lecturer; 
DENY UNMASK ON Student TO Lecturer; 



-- Grant unmask permission to Students to view their own grades
GRANT UNMASK ON Result TO Student;   
GRANT UNMASK ON Student TO Student;   

GO



-- ================================================================================================================
-- ================================================
-- Permissions for DataAdmin Role
-- Grant necessary access while denying sensitive columns like passwords and grades
-- ================================================

-- Grant full access to Student table, but deny access to the SystemPwd column
GRANT SELECT, INSERT, UPDATE, DELETE ON Student TO DataAdmin;				 
DENY SELECT ON Student(SystemPwd) TO DataAdmin;							-- Prevent access to passwords


-- Grant full access to Lecturer table, but deny access to the SystemPwd column
GRANT SELECT, INSERT, UPDATE, DELETE ON Lecturer TO DataAdmin;				
DENY SELECT ON Lecturer(SystemPwd) TO DataAdmin;						-- Prevent access to passwords

-- Grant full access to Subject table
GRANT SELECT, INSERT, UPDATE, DELETE ON Subject TO DataAdmin;

-- Grant full access to Result table, but deny access to the Grade column
GRANT SELECT, DELETE ON Result TO DataAdmin;
--DENY SELECT ON Result(Grade) TO DataAdmin;             -- Prevent access to student grade
GO


-- ================================================
-- Permissions for Lecturer Role
-- Allow Lecturers to manage specific columns while restricting DELETE and ALTER permissions
-- ================================================

-- Grant permission to update their own password and phone number only
GRANT SELECT, UPDATE ON Lecturer(SystemPwd, Phone) TO Lecturer;  -- Allow Lecturer to update password and phone number

-- Grant full access to manage the Result table
GRANT SELECT, INSERT, UPDATE ON Result TO Lecturer;

-- Grant SELECT access to the Student table, but deny access to the SystemPwd column
GRANT SELECT ON Student TO Lecturer;
DENY UPDATE,INSERT ON Student To Lecturer;
DENY SELECT ON Student(SystemPwd) TO Lecturer;  -- Prevent Lecturer from accessing student passwords

-- Grant SELECT access to the Subject table, but deny access to the SystemPwd column
GRANT SELECT ON Subject TO Lecturer;

-- Deny DELETE permissions on all major tables for Lecturer
DENY DELETE ON Student TO Lecturer;
DENY DELETE ON Lecturer TO Lecturer;
DENY DELETE ON Result TO Lecturer;
DENY DELETE ON Subject TO Lecturer;

-- Deny ALTER permission on the entire database for Lecturer
DENY ALTER ON DATABASE::AIS TO Lecturer;
GO


-- ================================================
-- Permissions for Student Role
-- Restrict Students from modifying or viewing sensitive data
-- ================================================

-- Grant SELECT access on the Subject table to Student
GRANT SELECT ON Subject TO Student;
GRANT SELECT, UPDATE ON Student TO Student;


-- Deny all permissions (SELECT, INSERT, UPDATE, DELETE) on the Lecturer, Student, and Result tables to Student
DENY SELECT, INSERT, UPDATE, DELETE ON Lecturer TO Student;
DENY INSERT, DELETE ON Student TO Student;
DENY SELECT, INSERT, UPDATE, DELETE ON Result TO Student;

-- Deny ALTER permission on the entire database for Student
DENY ALTER ON DATABASE::AIS TO Student;
GO


-- ================================================================================================
-- ================================================
-- Granting ALTER ANY LOGIN Permission to Specific Logins
-- This allows users (A001, A002, L001, L002, S001, etc.) to create or alter logins
-- ================================================

USE master;
GO

-- Grant ALTER ANY LOGIN to Admin1 and Admin2 logins (A001 and A002)
GRANT ALTER ANY LOGIN TO A001;  -- Grant to A001 (Admin1)
GRANT ALTER ANY LOGIN TO A002;  -- Grant to A002 (Admin2)

-- Grant ALTER ANY LOGIN to Lecturer and Student logins (L001, L002, S001, S002)
GRANT ALTER ANY LOGIN TO L001;  -- Grant to L001 (Lecturer1)
GRANT ALTER ANY LOGIN TO L002;  -- Grant to L002 (Lecturer2)
GRANT ALTER ANY LOGIN TO S001;  -- Grant to S001 (Student1)
GRANT ALTER ANY LOGIN TO S002;  -- Grant to S002 (Student2)
GO


-- ================================================
-- Granting ALTER ANY USER Permission to A001 and A002 (Admins)
-- This allows Admin1 and Admin2 to create or alter database users
-- ================================================

USE AIS;
GO

-- Grant ALTER ANY USER to Admin1 and Admin2 database users
GRANT ALTER ANY USER TO A001;  -- Allow Admin1 (A001) to alter users
GRANT ALTER ANY USER TO A002;  -- Allow Admin2 (A002) to alter users

GO

-- ================================================
-- Granting ALTER ANY ROLE Permission to A001 and A002 (Admins)
-- This allows Admin1 and Admin2 to create or alter roles in the database
-- ================================================

-- Grant ALTER ANY ROLE to Admin1 and Admin2 database users
GRANT ALTER ANY ROLE TO A001;  -- Allow Admin1 (A001) to alter roles
GRANT ALTER ANY ROLE TO A002;  -- Allow Admin2 (A002) to alter roles

GO



------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                 ---ADMIN--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- a.	add a lecturer or a student (add DB user, add to role, add row into Lecturer / Student table etc) with a temporary default password
-- a1.	add a lecturer with a temporary pasword
CREATE OR ALTER PROCEDURE sp_AddLecturer
    @LecturerLogin VARCHAR(256),      -- The lecturer's login ID 
    @LecturerPwd VARCHAR(max),        -- Temporary password
    @LecturerName NVARCHAR(100),      -- Lecturer's full name
    @LecturerPhone NVARCHAR(20),      -- Lecturer's phone number
    @LecturerDept NVARCHAR(30)        -- Lecturer's department
AS
BEGIN
    -- Step 1: Check if a SQL Server login with the same LecturerLogin already exists
    IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = @LecturerLogin)
    BEGIN
        RAISERROR('SQL Server login %s already exists.', 16, 1, @LecturerLogin);
        RETURN;  -- Stop execution
    END

    -- Step 2: Open the symmetric key for decryption
    OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';

    -- Step 3: Check if a lecturer with the same LecturerLogin already exists in the Lecturer table
    IF EXISTS (SELECT 1 FROM Lecturer WHERE CONVERT(VARCHAR(256), DECRYPTBYKEY(ID)) = @LecturerLogin)
    BEGIN
        -- If the LecturerLogin exists in the Lecturer table, raise an error and stop execution
        RAISERROR('Lecturer with ID %s already exists in the database.', 16, 1, @LecturerLogin);
        
        -- Close the symmetric key and stop execution
        CLOSE SYMMETRIC KEY LecturerIDKey;
        RETURN;
    END

    -- Step 4: Create a new SQL Server login
    EXEC ('CREATE LOGIN ' + @LecturerLogin + ' WITH PASSWORD = ''' + @LecturerPwd + ''';');

    -- Step 5: Create a database user for the lecturer in the AIS database
    EXEC ('CREATE USER ' + @LecturerName + ' FOR LOGIN ' + @LecturerLogin + ';');

    -- Step 6: Add the user to the Lecturer role in the AIS database
    EXEC ('ALTER ROLE Lecturer ADD MEMBER ' + @LecturerName + ';');

    -- Step 7: Encrypt the Lecturer ID and Password before inserting into the Lecturer table
    INSERT INTO Lecturer (ID, [SystemPwd], Name, Phone, Department)
    VALUES (
        ENCRYPTBYKEY(KEY_GUID('LecturerIDKey'), @LecturerLogin),  -- Encrypt Lecturer ID
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), @LecturerPwd),   -- Encrypt temporary password
        @LecturerName,
        @LecturerPhone,
        @LecturerDept
    );

    -- Step 8: Close the symmetric key after use
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON sp_AddLecturer TO DataAdmin


-- a2. add a student with temporary password
CREATE OR ALTER PROCEDURE sp_AddStudent
    @StudentLogin VARCHAR(6),        -- The student's login ID (e.g., S001)
    @StudentPwd VARCHAR(max),        -- Temporary password (to be encrypted)
    @StudentName NVARCHAR(100),       -- Student's full name
    @StudentPhone NVARCHAR(20)        -- Student's phone number
AS
BEGIN
    -- Step 0: Check if a student with the same StudentLogin already exists
    IF EXISTS (SELECT 1 FROM Student WHERE ID = @StudentLogin)
    BEGIN
        -- If the StudentLogin exists, raise an error and stop execution
        RAISERROR('Student with ID %s already exists.', 16, 1, @StudentLogin);
        RETURN;  -- Stop execution
    END

    -- Step 1: Create a new SQL Server login
    EXEC ('CREATE LOGIN ' + @StudentLogin + ' WITH PASSWORD = ''' + @StudentPwd + ''';');

    -- Step 2: Create a database user for the student in the AIS database
    EXEC ('CREATE USER ' + @StudentName + ' FOR LOGIN ' + @StudentLogin + ';');

    -- Step 3: Add the user to the Student role in the AIS database
    EXEC ('ALTER ROLE Student ADD MEMBER ' + @StudentName + ';');

    -- Step 4: Encrypt the Password before inserting into the Student table
    INSERT INTO Student (ID, [SystemPwd], Name, Phone)
    VALUES (
        @StudentLogin,  -- Student ID (plain text)
        ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), CONVERT(VARCHAR(100), @StudentPwd)),   -- Encrypt password
        @StudentName,
        @StudentPhone
    );
END;
GO

GRANT EXECUTE ON sp_AddStudent To DataAdmin


-- b. read and update lecturer’s or student’s data except password (2 Views, 2 SP)
-- b1. read student's data except password
CREATE OR ALTER Procedure SP_Admin_ViewStudent
AS
BEGIN 
    SELECT 
        ID,
        Name, 
        Phone AS Unmasked_Phone
    FROM 
        Student
END;
GO

GRANT EXECUTE ON SP_Admin_ViewStudent TO DataAdmin;


-- b2. read lecturer's data except password
CREATE OR ALTER Procedure SP_Admin_ViewLecturer 
AS
BEGIN
	-- Open the symmetric key for LecturerID decryption
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';  
 
    SELECT 
        CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) AS Decrypted_LecturerID,
        Name, 
        Phone AS Unmasked_Phone,
        Department
    FROM 
        Lecturer
 
    -- Close the symmetric key after the query
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON SP_Admin_ViewLecturer TO DataAdmin;


-- b3. update lecturer’s data except password 
CREATE OR ALTER PROCEDURE SP_AdminUpdateLecturer
(
    @LecturerLogin VARCHAR(256),     -- Lecturer's login ID
    @NewLecturerName NVARCHAR(100) = NULL,  -- New lecturer name (optional)
    @NewLecturerPhone NVARCHAR(20) = NULL,  -- New lecturer phone number (optional)
    @NewLecturerDept NVARCHAR(30) = NULL    -- New lecturer department (optional)
)
AS
BEGIN
    -- Step 1: Open the symmetric key used for encryption
    IF NOT EXISTS (SELECT 1 FROM sys.openkeys WHERE key_name = 'LecturerIDKey')
    BEGIN
        OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
    END

    -- Step 2: Check if the lecturer exists in the Lecturer table
    IF NOT EXISTS (SELECT 1 FROM Lecturer WHERE CONVERT(VARCHAR(256), DECRYPTBYKEY(ID)) = @LecturerLogin)
    BEGIN
        -- If the lecturer doesn't exist, raise an error and stop execution
        RAISERROR('Lecturer with ID %s does not exist.', 16, 1, @LecturerLogin);
        
        -- Close the symmetric key and stop execution
        CLOSE SYMMETRIC KEY LecturerIDKey;
        RETURN;
    END

    -- Step 3: Check if at least one field is provided for update
    IF @NewLecturerName IS NULL AND @NewLecturerPhone IS NULL AND @NewLecturerDept IS NULL
    BEGIN
        RAISERROR('At least one field (Name, Phone, or Department) must be provided for update.', 16, 1);
        
        -- Close the symmetric key and stop execution
        CLOSE SYMMETRIC KEY LecturerIDKey;
        RETURN;
    END

    -- Step 4: Update the lecturer's details based on the provided inputs
    UPDATE Lecturer
    SET 
        Name = ISNULL(@NewLecturerName, Name),      -- Update Name if provided
        Phone = ISNULL(@NewLecturerPhone, Phone),   -- Update Phone if provided
        Department = ISNULL(@NewLecturerDept, Department)  -- Update Department if provided
    WHERE CONVERT(VARCHAR(256), DECRYPTBYKEY(ID)) = @LecturerLogin;

    -- Step 5: Print a success message
    PRINT 'Lecturer details updated successfully.';

    -- Step 6: Close the symmetric key after use
	OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';

    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON SP_AdminUpdateLecturer TO DataAdmin;


-- b4. update student’s data except password 
CREATE OR ALTER PROCEDURE SP_AdminUpdateStudent
(
    @StudentLogin NVARCHAR(6),      -- Student's ID (Login ID)
    @NewStudentName NVARCHAR(100) = NULL,  -- New student name (optional)
    @NewStudentPhone NVARCHAR(20) = NULL   -- New student phone number (optional)
)
AS
BEGIN
    -- Step 1: Check if the student exists in the Student table
    IF NOT EXISTS (SELECT 1 FROM Student WHERE ID = @StudentLogin)
    BEGIN
        -- If the student doesn't exist, raise an error
        RAISERROR('Student with ID %s does not exist.', 16, 1, @StudentLogin);
        RETURN;  -- Stop execution
    END

    -- Step 2: Check if at least one field is provided for update
    IF @NewStudentName IS NULL AND @NewStudentPhone IS NULL
    BEGIN
        RAISERROR('At least one field (Name or Phone) must be provided for update.', 16, 1);
        RETURN;  -- Stop execution
    END

    -- Step 3: Update the student's name or phone based on the provided inputs
    UPDATE Student
    SET 
        Name = ISNULL(@NewStudentName, Name),    -- If a new name is provided, update it; otherwise, leave it unchanged
        Phone = ISNULL(@NewStudentPhone, Phone)  -- If a new phone is provided, update it; otherwise, leave it unchanged
    WHERE ID = @StudentLogin;

    -- Step 4: Print a success message
    PRINT 'Student details updated successfully.';
END;
GO

GRANT EXECUTE ON SP_AdminUpdateStudent TO DataAdmin;


-- c. add or modify data in the Subject table
-- c1. add data in the Subject table
CREATE OR ALTER PROCEDURE SP_AddSubject
(
    @Code VARCHAR(5),      
    @Title VARCHAR(30)     
)
AS
BEGIN
    -- Check if the subject already exists
    IF EXISTS (SELECT 1 FROM Subject WHERE Code = @Code)
    BEGIN
        RAISERROR('Subject with this code already exists.', 16, 1);
        RETURN;
    END

    -- Insert the new subject into the Subject table
    INSERT INTO Subject (Code, Title)
    VALUES (@Code, @Title);
    
    PRINT 'Subject added successfully.';
END;
GO

GRANT EXECUTE ON SP_AddSubject TO DataAdmin;


-- c2. modify data in the Subject table
CREATE OR ALTER PROCEDURE SP_AdminUpdateSubject
(
    @OldCode VARCHAR(5),      -- Existing subject code to identify the subject
    @NewCode VARCHAR(5),      -- New subject code to update
    @NewTitle VARCHAR(30)     -- New title for the subject
)
AS
BEGIN
    -- Check if the subject code exists in the Subject table
    IF NOT EXISTS (SELECT 1 FROM Subject WHERE Code = @OldCode)
    BEGIN
        RAISERROR('Subject with this code does not exist.', 16, 1);
        RETURN;
    END

    -- Check if the subject code and title already exist in the Result table
    IF EXISTS (SELECT 1 FROM Result WHERE SubjectCode = @OldCode)
    BEGIN
        RAISERROR('Subject code and title already exist in the Result table. Cannot modify.', 16, 1);
        RETURN;
    END
    ELSE
    BEGIN
        -- Update the subject code and title if they are not in the Result table
        UPDATE Subject
        SET Code = @NewCode, Title = @NewTitle
        WHERE Code = @OldCode;

        PRINT 'Subject updated successfully.';
    END
END;
GO

-- Grant execute permission on the stored procedure to the Admin role
GRANT EXECUTE ON SP_AdminUpdateSubject TO DataAdmin;


-- d. delete any data 
-- Option 1 - delete subject record that not in Result table
CREATE OR ALTER PROCEDURE SP_DeleteSubject
(
    @SubjectCode VARCHAR(5)  -- Subject code to identify the subject to be deleted
)
AS
BEGIN
    -- Check if the subject exists
    IF NOT EXISTS (SELECT 1 FROM Subject WHERE Code = @SubjectCode)
    BEGIN
        RAISERROR('Subject not found.', 16, 1);
        RETURN;
    END
    -- Check if the subject is associated with any records in the Result table
    IF EXISTS (SELECT 1 FROM Result WHERE SubjectCode = @SubjectCode)
    BEGIN
        RAISERROR('Cannot delete subject as it is associated with student results.', 16, 1);
        RETURN;
    END
    -- Delete the subject if not associated with any results
    DELETE FROM Subject
    WHERE Code = @SubjectCode;
    PRINT 'Subject deleted successfully.';
END;
GO
 
GRANT EXECUTE ON SP_DeleteSubject TO DataAdmin;


-- Option 2 - Admin Delete Result Record
CREATE OR ALTER PROCEDURE SP_DeleteResult
(
    @ResultID INT  -- The ID of the result record to be deleted
)
AS
BEGIN
    -- Check if the result record exists
    IF NOT EXISTS (SELECT 1 FROM Result WHERE ID = @ResultID)
    BEGIN
        RAISERROR('Result record not found.', 16, 1);
        RETURN;
    END
    -- Delete the result record
    DELETE FROM Result
    WHERE ID = @ResultID;
    PRINT 'Result record deleted successfully.';
END;
GO

GRANT EXECUTE ON SP_DeleteResult TO DataAdmin;


-- e. track deleted data  
-- Admin track  deleted / modified subject data
CREATE OR ALTER PROCEDURE SP_TrackSubjectData
AS
BEGIN
    -- Select all deleted records from the history table
    SELECT *
    FROM SubjectHistory
    WHERE ValidTo <> '9999-12-31 23:59:59.9999999';  -- This identifies deleted records
END;
GO
 
GRANT EXECUTE ON SP_TrackSubjectData TO DataAdmin;

 
-- Admin track deleted / modified result record
CREATE OR ALTER PROCEDURE SP_TrackResultData
AS
BEGIN
    -- Select all deleted records from the history table
    SELECT *
    FROM ResultHistory
    WHERE ValidTo <> '9999-12-31 23:59:59.9999999';  -- This identifies deleted records
END;
GO
 
GRANT EXECUTE ON SP_TrackResultData TO DataAdmin;


-- f. recover selected deleted any data 
-- admin recover deleted / modified subject data
CREATE OR ALTER PROCEDURE SP_RecoverSubjectData
    @Code VARCHAR(5),       -- Code of the subject to recover
    @ValidFrom DATETIME2      -- ValidFrom timestamp of the record to recover
AS
BEGIN
    -- Check if the record exists in the SubjectHistory table with the given conditions
    IF EXISTS (
        SELECT 1 
        FROM SubjectHistory
        WHERE ValidTo <> '9999-12-31 23:59:59.9999999'  -- Select only deleted records
        AND Code = @Code                                 -- Match on the Code
        AND ValidFrom = @ValidFrom                       -- Match on the specific timestamp
    )
    BEGIN
        -- Insert the selected deleted record back into the Subject table
        INSERT INTO Subject (Code, Title)
        SELECT Code, Title
        FROM SubjectHistory
        WHERE ValidTo <> '9999-12-31 23:59:59.9999999'
        AND Code = @Code
        AND ValidFrom = @ValidFrom;

        -- Notify that the recovery was successful
        PRINT 'Selected deleted record has been successfully recovered into the Subject table.';
    END
    ELSE
    BEGIN
        -- Notify that the recovery was unsuccessful due to mismatching data
        PRINT 'Error: The specified record with the given ValidFrom and Code does not exist or is not marked as deleted.';
    END
END;
GO

GRANT EXECUTE ON SP_RecoverSubjectData TO DataAdmin;

 
 -- admin recover deleted result data
CREATE OR ALTER PROCEDURE SP_RecoverResultByID
    @ID INT,  -- Parameter to select the specific record based on ID
    @ExpectedValidTo DATETIME2 -- Expected time of deletion

AS
BEGIN
    -- Insert the deleted record back into the Result table
    INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
    SELECT StudentID, LecturerID, SubjectCode, AssessmentDate, Grade
    FROM ResultHistory
    WHERE ValidTo <> '9999-12-31 23:59:59.9999999'  -- Only deleted records
    AND ID = @ID;  -- Recover only the record with the matching ID
 
    -- Optional: Notify that the recovery was successful
    PRINT 'The selected deleted result has been successfully recovered into the Result table.';
END;
GO

GRANT EXECUTE ON SP_RecoverResultByID TO DataAdmin;



------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                 ---Lecturer--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- a. read and update own data - including password and any encrypted /hashed values
-- a1. read own data - including password and any encrypted /hashed values
CREATE OR ALTER PROCEDURE SP_Lecturer_ViewDetails  
AS
BEGIN
    -- Open the symmetric key for LecturerID decryption
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';  

    -- Fetch the lecturer's details, including decrypted password
    SELECT 
        CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) AS Decrypted_LecturerID,  -- Decrypt LecturerID
        Name, 
		-- Decrypt the password stored in SystemPwd using the asymmetric key
		CONVERT(VARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS Devrypted_Password,
        Phone AS Unmasked_Phone, 
        Department
    FROM 
        Lecturer
    WHERE 
        CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = SYSTEM_USER;

    -- Close the symmetric key after the query
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON SP_Lecturer_ViewDetails TO Lecturer;


-- a2. update own data - including password and any encrypted /hashed values
CREATE OR ALTER PROCEDURE SP_Lecturer_UpdateDetails
    @NewPhone VARCHAR(20) = NULL,
    @NewPwd NVARCHAR(100) = NULL  -- Use NVARCHAR for the plain text password
AS
BEGIN
	-- Step 1: Get the current user's login (SYSTEM_USER gives us the SQL Server login)
    DECLARE @LecturerLogin NVARCHAR(100);
    DECLARE @CurrentPwd NVARCHAR(100);    -- Variable to store the current decrypted password
	DECLARE @Message NVARCHAR(100) = '';

	-- Open the symmetric key for LecturerID decryption
	OPEN SYMMETRIC KEY LecturerIDKey
	DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';

    SET @LecturerLogin = SYSTEM_USER;

	-- Step 2: Update phone number if provided
    IF @NewPhone IS NOT NULL
    BEGIN
        UPDATE Lecturer
        SET Phone = @NewPhone
        WHERE CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = @LecturerLogin;
		SET @Message = 'Phone updated successfully.';
    END

	-- Step 3: Update password if provided and it's different from the current password
    IF @NewPwd IS NOT NULL
    BEGIN
        -- Retrieve the current password (decrypted)
        SELECT @CurrentPwd = CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd))
        FROM Lecturer
        WHERE CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = @LecturerLogin;

        -- Check if the new password is the same as the current password
        IF @CurrentPwd = @NewPwd
        BEGIN
            PRINT 'The new password cannot be the same as the current password.';
			RETURN;
        END
        ELSE
        BEGIN
            -- Update the SQL Server login password
            EXEC ('ALTER LOGIN ' + @LecturerLogin + ' WITH PASSWORD = ''' + @NewPwd + ''';');
        
            -- Update the encrypted password in the Student table
            UPDATE Lecturer
            SET SystemPwd = ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), CONVERT(NVARCHAR(100), @NewPwd))
            WHERE CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = @LecturerLogin;

            -- Update the message
            IF @Message = '' 
                SET @Message = 'Password updated successfully.';
            ELSE
                SET @Message = 'Phone and password updated successfully.';  -- Both phone and password were updated
        END
    END

    -- Step 4: Print the appropriate message
    PRINT @Message;

    -- Step 5: Return the updated lecturer information as confirmation
    SELECT 
        CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) AS Decrypted_LecturerID, 
		CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS Decrypted_Password,
        Name, 
        Phone AS Unmasked_Phone, 
		Department
    FROM Lecturer
    WHERE CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = @LecturerLogin;

	-- Close the symmetric keys after the operation
	CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON SP_Lecturer_UpdateDetails TO Lecturer;


-- b. add new results and update results (grades) for a few students
-- b1. add new results for a few students
CREATE OR ALTER PROCEDURE SP_LecturerAddResult
(
    @StudentID VARCHAR(6),          
    @SubjectCode VARCHAR(5),      
    @AssessmentDate DATE,       
    @Grade VARCHAR(2)          
)
AS
BEGIN
    -- Open the symmetric key to decrypt the LecturerID
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
 
    -- Decrypt the LecturerID based on the logged-in SYSTEM_USER
    DECLARE @LecturerID VARBINARY(256);
    SELECT @LecturerID = ID 
    FROM Lecturer
    WHERE CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) = SYSTEM_USER;  
 
    -- Check if the lecturer exists
    IF @LecturerID IS NULL
    BEGIN
        RAISERROR('Lecturer not found.', 16, 1);
        RETURN;
    END
 
    -- Check if the student exists
    IF NOT EXISTS (SELECT 1 FROM Student WHERE ID = @StudentID)
    BEGIN
        RAISERROR('Student does not exist.', 16, 1);
        RETURN;
    END
 
    -- Check if the subject exists
    IF NOT EXISTS (SELECT 1 FROM Subject WHERE Code = @SubjectCode)
    BEGIN
        RAISERROR('Subject code does not exist.', 16, 1);
        RETURN;
    END
 
    -- Check if the result already exists for the given StudentID, SubjectCode, and AssessmentDate
    IF EXISTS (SELECT 1 
               FROM Result 
               WHERE StudentID = @StudentID 
                 AND SubjectCode = @SubjectCode 
                 AND AssessmentDate = @AssessmentDate)
    BEGIN
        -- If the record exists, raise an error or show a message
        RAISERROR('The result record already exists for this student.', 16, 1);
        RETURN;
    END
 
    -- Insert the result record with the encrypted LecturerID
    INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate, Grade)
    VALUES 
    (
        @StudentID,                 -- Insert the student ID
        @LecturerID,                -- Insert the encrypted Lecturer ID
        @SubjectCode,               -- Insert the subject code
        @AssessmentDate,            -- Insert the assessment date
        @Grade                      -- Insert the grade
    );
 
    -- Print success message
    PRINT 'Student result added successfully';
 
    -- Close the symmetric key after use
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO
 
GRANT EXECUTE ON SP_LecturerAddResult TO Lecturer;


-- b2. update results (grades) for a few students
CREATE OR ALTER PROCEDURE SP_LecturerUpdateResult 
(
    @StudentID VARCHAR(6),           -- Student's ID
    @SubjectCode VARCHAR(5),         -- Subject code
    @AssessmentDate DATE,            -- Assessment Date
    @NewGrade VARCHAR(2)             -- New grade to update
)
AS
BEGIN
    -- Open the symmetric key for decryption
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
 
    -- Get the lecturer's SQL Server login (SYSTEM_USER)
    DECLARE @LecturerLogin NVARCHAR(256);
    SET @LecturerLogin = SYSTEM_USER;
 
    -- Decrypt the LecturerID using the SYSTEM_USER (SQL Server login)
    DECLARE @LecturerID VARBINARY(256);
    SELECT @LecturerID = ID 
    FROM Lecturer
    WHERE CONVERT(VARCHAR(256), DECRYPTBYKEY(ID)) = @LecturerLogin;
 
    -- Check if the LecturerID was found
    IF @LecturerID IS NULL
    BEGIN
        RAISERROR('Lecturer not found.', 16, 1);
        CLOSE SYMMETRIC KEY LecturerIDKey;
        RETURN;
    END
 
    -- Check if the student exists
    IF NOT EXISTS (SELECT 1 FROM Student WHERE ID = @StudentID)
    BEGIN
        RAISERROR('Student does not exist.', 16, 1);
        RETURN;
    END
 
    -- Check if the subject exists
    IF NOT EXISTS (SELECT 1 FROM Subject WHERE Code = @SubjectCode)
    BEGIN
        RAISERROR('Subject code does not exist.', 16, 1);
        RETURN;
    END
 
    -- Check if the result exists for the given StudentID, SubjectCode, and AssessmentDate
    IF NOT EXISTS (SELECT 1 
                   FROM Result 
                   WHERE StudentID = @StudentID 
                   AND SubjectCode = @SubjectCode 
                   AND AssessmentDate = @AssessmentDate
                   AND LecturerID = @LecturerID)
    BEGIN
        -- If the record does not exist or does not belong to the logged-in lecturer, raise an error
        RAISERROR('No result record found for this student or you are not authorized to update this record.', 16, 1);
        CLOSE SYMMETRIC KEY LecturerIDKey;
        RETURN;
    END
 
    -- Update the grade in the Result table only if the conditions are met
    UPDATE Result
    SET Grade = @NewGrade
    WHERE StudentID = @StudentID 
      AND SubjectCode = @SubjectCode 
      AND AssessmentDate = @AssessmentDate
      AND LecturerID = @LecturerID;
 
    -- Print success message
    PRINT 'Student result updated successfully';
 
    -- Close the symmetric key after use
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO
 
GRANT EXECUTE ON SP_LecturerUpdateResult TO Lecturer;


-- c. read lecturer’s or student’s data except password (any personal & sensitive information not allowed)

-- c1. View Lecturer's data
CREATE OR ALTER Procedure SP_View_Lecturer 
AS
BEGIN
	-- Open the symmetric key for LecturerID decryption
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';  

    -- Select other lecturers' details, excluding the logged-in lecturer
    SELECT 
        ID AS Encrypted_ID,  -- Show encrypted LecturerID
        Name, 
        'XXX-XXX-' + RIGHT(Phone, 4) AS MaskedPhone,  
        Department
    FROM 
        Lecturer
    WHERE 
        CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) != SYSTEM_USER;  -- Exclude own details

    -- Close the symmetric key after the query
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

GRANT EXECUTE ON SP_View_Lecturer TO Lecturer;


-- c2. View Student's data
CREATE OR ALTER VIEW Lecturer_ViewStudent AS
SELECT 
    ID AS StudentID,
    Name AS StudentName,
    Phone AS Masked_StudentPhone
FROM 
    Student;
GO

GRANT SELECT ON Lecturer_ViewStudent TO Lecturer;


-- d. read all students result including results added by other lecturers
CREATE OR ALTER PROCEDURE SP_LecturerViewResult
AS
BEGIN
    -- Open the symmetric key to decrypt the LecturerID
    OPEN SYMMETRIC KEY LecturerIDKey
    DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';  -- Replace with your actual key password

    -- Select all results from the Result table, along with student, subject, and lecturer information
    SELECT 
        r.ID AS ResultID,
        s.Name AS StudentName,
        r.StudentID,
        r.SubjectCode,
        sub.Title AS SubjectTitle,
        r.AssessmentDate,
        r.Grade,
        l.ID,  -- Decrypt LecturerID
        l.Name AS LecturerName
    FROM 
        Result r
    JOIN 
        Student s ON r.StudentID = s.ID
    JOIN 
        Subject sub ON r.SubjectCode = sub.Code
    JOIN 
        Lecturer l ON r.LecturerID = l.ID;

    -- Close the symmetric key after the query
    CLOSE SYMMETRIC KEY LecturerIDKey;
END;
GO

-- Grant permission to execute the stored procedure to the Lecturer role
GRANT EXECUTE ON SP_LecturerViewResult TO Lecturer;


-- e. read subject table
CREATE OR ALTER VIEW View_Subject AS
SELECT 
	Code AS SubjectCode,
    Title AS SubjectTitle
FROM 
    Subject
GO

GRANT SELECT ON View_Subject TO Lecturer


-- f. update other lecturer’s data 
CREATE FUNCTION dbo.fn_LecturerSecurityPredicate(@LecturerID VARBINARY(256))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN (
    -- The function returns true if the decrypted Lecturer ID matches the current user's login
    SELECT 1 AS fn_security_predicate_result
    WHERE CONVERT(VARCHAR(256), DECRYPTBYKEY(@LecturerID)) = SYSTEM_USER
	OR SYSTEM_USER LIKE 'A_%'  -- Add this condition to allow Admins
);
GO


-- Create the security policy for the Lecturer table
CREATE SECURITY POLICY LecturerSecurityPolicy
-- Prevent lecturers from updating data for other lecturers
ADD BLOCK PREDICATE dbo.fn_LecturerSecurityPredicate(ID) ON dbo.Lecturer AFTER UPDATE; 
GO




------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                 ---Student--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- a. read own data - If there is any encryption done, then those values must be decrypted automatically. 
CREATE OR ALTER VIEW View_StudentOwn AS
SELECT ID,
       CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS DecryptedPassword,
       Name,
       Phone
FROM Student
WHERE ID = SYSTEM_USER;  
GO

GRANT SELECT ON View_StudentOwn TO Student;


-- b. update own data  including password and any encrypted /hashed values
CREATE OR ALTER PROCEDURE sp_UpdateStudentDetails
    @NewPhone NVARCHAR(20) = NULL,       -- New phone number (optional)
    @NewPwd NVARCHAR(100) = NULL         -- New password (optional)
AS
BEGIN
    -- Step 1: Get the current user's login (SYSTEM_USER gives us the SQL Server login)
    DECLARE @StudentLogin NVARCHAR(100);
    DECLARE @CurrentPwd NVARCHAR(100);    -- Variable to store the current decrypted password
	DECLARE @Message NVARCHAR(100) = '';

    SET @StudentLogin = SYSTEM_USER;

    -- Step 2: Update phone number if provided
    IF @NewPhone IS NOT NULL
    BEGIN
        UPDATE Student
        SET Phone = @NewPhone
        WHERE ID = @StudentLogin;
		SET @Message = 'Phone updated successfully.';
    END

    -- Step 3: Update password if provided and it's different from the current password
    IF @NewPwd IS NOT NULL
    BEGIN
        -- Retrieve the current password (decrypted)
        SELECT @CurrentPwd = CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd))
        FROM Student
        WHERE ID = @StudentLogin;

        -- Check if the new password is the same as the current password
        IF @CurrentPwd = @NewPwd
        BEGIN
            PRINT 'The new password cannot be the same as the current password.';
			RETURN;
        END
        ELSE
        BEGIN
            -- Update the SQL Server login password
            EXEC ('ALTER LOGIN ' + @StudentLogin + ' WITH PASSWORD = ''' + @NewPwd + ''';');
        
            -- Update the encrypted password in the Student table
            UPDATE Student
            SET SystemPwd = ENCRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), CONVERT(NVARCHAR(100), @NewPwd))
            WHERE ID = @StudentLogin;

            -- Update the message
            IF @Message = '' 
                SET @Message = 'Password updated successfully.';
            ELSE
                SET @Message = 'Update successful.';  -- Both phone and password were updated
        END
    END

    -- Step 4: Print the appropriate message
    PRINT @Message;

    -- Step 5: Return the updated student information as confirmation
    SELECT 
        ID, 
        Name, 
        Phone, 
        CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS DecryptedPassword
    FROM Student
    WHERE ID = @StudentLogin;
END;
GO

GRANT EXECUTE ON sp_UpdateStudentDetails TO Student;


-- c. read own results
CREATE OR ALTER VIEW View_ResultOwn AS
SELECT r.ID AS ResultID,
       r.StudentID,
       s.Name AS StudentName,
       r.SubjectCode,
       sub.Title AS SubjectTitle,
       r.AssessmentDate,
       r.Grade
FROM Result r
JOIN Student s ON r.StudentID = s.ID
JOIN Subject sub ON r.SubjectCode = sub.Code
WHERE r.StudentID = SYSTEM_USER;  
GO

GRANT SELECT ON View_ResultOwn TO Student;


-- d. read subject table
GRANT SELECT ON View_Subject TO Student;


-- g. cannot add or modify any data except their personal details in the Student data

-- Function to block INSERT actions by students
-- Security predicate function for student updates (ensures students can only update their own record)
CREATE FUNCTION dbo.fn_StudentSecurityPredicate(@StudentID VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN (
    -- Allow access only to the student with a matching StudentID
    SELECT 1 AS fn_student_security_predicate_result
    WHERE @StudentID = SYSTEM_USER
	OR SYSTEM_USER LIKE 'A_%'  -- Add this condition to allow Admins

);
GO

-- Create the security policy for the Student table
CREATE SECURITY POLICY StudentSecurityPolicy
ADD BLOCK PREDICATE dbo.fn_StudentSecurityPredicate(ID) ON dbo.Student AFTER UPDATE;  -- Block update if StudentID doesn't match
GO





-------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------
-- Query to show the permissions for roles
SELECT 
    dp.name AS RoleName,
    o.name AS ObjectName,
    p.permission_name AS Permission,
    p.state_desc AS PermissionState
FROM 
    sys.database_permissions AS p
JOIN 
    sys.database_principals AS dp ON p.grantee_principal_id = dp.principal_id
JOIN 
    sys.objects AS o ON p.major_id = o.object_id
WHERE 
    dp.name IN ('DataAdmin','Lecturer','Student')  -- Filter by roles 
ORDER BY 
    dp.name, o.name, p.permission_name;
GO


use AIS
