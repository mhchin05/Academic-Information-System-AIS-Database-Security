-- STUDENT

USE AIS

-- a. Read Own Data
SELECT * FROM View_StudentOwn;


-- b.  Update Own Data
EXEC sp_UpdateStudentDetails
    @NewPwd = 'Temp781',  -- New password (optional)
    @NewPhone = '012-1313123';   -- New phone number (optional)
GO

EXEC sp_UpdateStudentDetails
    @NewPhone = '018-9876543';  -- Only update phone number
GO

EXEC sp_UpdateStudentDetails
    @NewPwd = 'Student123' ;    -- Only update password
GO


-- c. Read own result
SELECT * FROM View_ResultOwn;


-- d. View subject
SELECT * FROM  View_Subject;


-- Query
-- e. Cannot view lecturer detail
SELECT * FROM Lecturer;


-- f. Cannot view other student detail
SELECT * FROM Student;


-- f. Cannot view other student result
SELECT * FROM Result;


-- g. Cannot add or update other student detail
UPDATE Student
SET Name = 'Student123'
WHERE ID = 'S001';	


-- h. Cannot delete any record
DELETE FROM Student;
DELETE FROM Lecturer;
DELETE FROM Result;
DELETE FROM Subject;


-- i. Cannot drop table, procedure, view
DROP TABLE Student;
DROP TABLE Result;
DROP TABLE Lecturer;
DROP TABLE Subject;
DROP VIEW View_ResultOwn;
DROP VIEW View_StudentOwn;
DROP VIEW View_Subject;


-- Check the permissions granted to the Student role 
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
    dp.name = 'Student';
GO



