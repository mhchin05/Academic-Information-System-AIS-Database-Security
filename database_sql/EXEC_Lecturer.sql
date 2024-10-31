-- LECTURER

USE AIS
GO

-- a. Read own details
EXEC SP_Lecturer_ViewDetails ;


-- a. Update own detail
EXEC SP_Lecturer_UpdateDetails 
    @NewPhone = '013-2132732',
	@NewPwd = 'Lecturer456'
GO


-- b. Add new result for a few students
EXEC SP_LecturerAddResult 
    @StudentID = 'S001', 
    @SubjectCode = 'MATH1', 
    @AssessmentDate = '2024-07-29', 
    @Grade = 'C';
GO


-- b. Update result(grades) for a few students
EXEC SP_LecturerUpdateResult 
	@StudentID = 'S001', 
	@SubjectCode = 'ENG1', 
	@AssessmentDate = '2024-07-29', 
	@NewGrade = 'F';
GO


-- c. View other lecturer detail except password (own assumptions, other encrypted & masked not allowed)
EXEC SP_View_Lecturer;


-- c. View other student detail except passsword (Views)
Select * FROM Lecturer_ViewStudent;


-- d. View result
EXEC SP_LecturerViewResult;


-- e. View subject
SELECT * FROM View_Subject;


-- f. Cannot update other lecturer details
-- validation set in (a) where lecturer only can update own details upon login
UPDATE Lecturer
SET
    Phone = '012-4442222'               
WHERE
    Name = 'Lecturer3'      

-- g. Cannot update student detail
UPDATE Student
SET
    Name = 'Student1',       -- Update the student's name
    Phone = '012-4445555'    -- Update the student's phone number
WHERE
    ID = 'S001';             -- Specify the Student ID

-- h. Cannot Update grade added by other lecturer
EXEC SP_LecturerUpdateResult
	@StudentID = 'S002',
    @SubjectCode = 'MATH1', 
	@AssessmentDate = '2024-07-29',
    @NewGrade = 'D'
GO


-- i. Cannot delete any record from any table
DELETE FROM Student;
DELETE FROM Lecturer;
DELETE FROM Result;
DELETE FROM Subject;


-- j. Cannot drop table, procedure, view 
DROP TABLE Student;
DROP TABLE Result;
DROP TABLE Lecturer;
DROP TABLE Subject;
DROP VIEW View_Subject;
DROP PROCEDURE SP_Lecturer_ViewDetails;
DROP PROCEDURE SP_LecturerAddResult;
DROP PROCEDURE View_Lecturer


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
    dp.name = 'Lecturer';
GO


