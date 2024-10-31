USE AIS;
GO
-- =======================================================================
--1. Query to show unique permissions granted to each role in the database
-- =======================================================================

SELECT DISTINCT
    DP1.name AS RoleName,
    O.name AS ObjectName,
    P.permission_name AS PermissionType,
    P.state_desc AS PermissionState
FROM 
    sys.database_principals DP1
JOIN 
    sys.database_role_members DRM ON DP1.principal_id = DRM.role_principal_id
JOIN 
    sys.database_permissions P ON DP1.principal_id = P.grantee_principal_id
JOIN 
    sys.objects O ON P.major_id = O.object_id
WHERE 
    DP1.type = 'R'  -- Filter for roles only
GROUP BY 
    DP1.name, O.name, P.permission_name, P.state_desc;
GO

USE AIS;
GO

-- =====================================================================
--2. Query to show the members of DataAdmin, Lecturer, and Student roles
-- =====================================================================

SELECT 
    DP1.name AS RoleName,    -- The role name (DataAdmin, Lecturer, Student)
    DP2.name AS UserName     -- The user who is a member of the role
FROM 
    sys.database_role_members AS DRM
JOIN 
    sys.database_principals AS DP1 ON DRM.role_principal_id = DP1.principal_id  -- Role
JOIN 
    sys.database_principals AS DP2 ON DRM.member_principal_id = DP2.principal_id  -- Member
WHERE 
    DP1.name IN ('DataAdmin', 'Lecturer', 'Student');   -- Filter for specific roles
GO


-- ====================================================
-- SuperAdmin Viewing Decrypted Data from Student Table
-- ====================================================

USE AIS;
GO

-- Select all columns from Student table and decrypt the SystemPwd (Password)
SELECT 
    ID,                      -- Student ID
	CONVERT(NVARCHAR(100), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS DecryptedPassword,  -- Decrypt password
    Name,                    -- Student Name
    Phone                    -- Student Phone (Not encrypted)
FROM 
    Student;
GO

-- ================================================
-- SuperAdmin Viewing Decrypted Data from Lecturer Table
-- ================================================

USE AIS;
GO

-- Step 1: Open the symmetric key for decryption
OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO

-- Step 2: Select all columns from Lecturer table and decrypt the sensitive columns
SELECT 
    CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) AS DecryptedLecturerID,   -- Decrypted Lecturer ID
	CONVERT(VARCHAR(MAX), DECRYPTBYASYMKEY(ASYMKEY_ID('MyRSAKey'), SystemPwd)) AS DecryptedPassword,  -- Decrypted password
    Name,                    -- Lecturer Name
    Phone,                   -- Lecturer Phone
    Department              -- Lecturer Department
FROM 
    Lecturer;
GO

-- Step 3: Close the symmetric key after use to maintain security
CLOSE SYMMETRIC KEY LecturerIDKey;
GO


-- ================================================
-- SuperAdmin Viewing Decrypted Data from Result Table
-- ================================================

USE AIS;
GO

-- Step 1: Open the symmetric key to decrypt sensitive columns (e.g., Lecturer ID)
OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO

-- Step 2: Select all columns from Result table and decrypt the LecturerID
SELECT 
    ID,                             -- Result Table ID (Auto-generated)
    StudentID,                      -- Student ID (Foreign Key from Student Table)
    CONVERT(VARCHAR(100), DECRYPTBYKEY(LecturerID)) AS DecryptedLecturerID,   -- Decrypted Lecturer ID
    SubjectCode,                    -- Subject Code (Foreign Key from Subject Table)
    AssessmentDate,                 -- Date of Assessment
    Grade                           -- Grade Received by Student
FROM 
    Result;
GO

-- Step 3: Close the symmetric key after use to maintain security
CLOSE SYMMETRIC KEY LecturerIDKey;
GO

-- ================================================
-- SuperAdmin Viewing Decrypted Data from Subject Table
-- ================================================
SELECT 
    Code,          -- Subject Code (Primary Key)
	Title          -- Title of the subject Code

FROM 
    Subject;
GO

-- ================================================
-- Query to check the status of the latest backup jobs
-- ================================================
SELECT job.name AS JobName,
       h.run_date AS LastRunDate,
       h.run_time AS LastRunTime,
       CASE 
           WHEN h.run_status = 0 THEN 'Failed'
           WHEN h.run_status = 1 THEN 'Succeeded'
           WHEN h.run_status = 2 THEN 'Retry'
           ELSE 'Unknown'
       END AS JobStatus
FROM msdb.dbo.sysjobs job
JOIN msdb.dbo.sysjobhistory h ON job.job_id = h.job_id
WHERE job.name = 'AutomatedDatabaseBackup'
AND h.step_id = 0  -- Only get results for the final job outcome
ORDER BY h.run_date DESC, h.run_time DESC;


-- ================================================
-- Check if TDE is enabled on the database
-- ================================================

-- Backup the TDE Database
USE master
Go
BACKUP DATABASE AIS  
TO DISK = 'C:\Backup\AIS_TDE.bak'
WITH FORMAT;
GO

SELECT name, is_encrypted
FROM sys.databases
WHERE name = 'AIS';  
GO

Use master
SELECT * FROM sys.symmetric_keys
SELECT * FROM sys.certificates
SELECT db_name(a.database_id) AS DBName , a.encryption_state_desc, 
a.encryptor_type , b.name as 'DEK Encrypted By'
FROM sys.dm_database_encryption_keys a
INNER JOIN sys.certificates b ON a.encryptor_thumbprint = b.thumbprint







