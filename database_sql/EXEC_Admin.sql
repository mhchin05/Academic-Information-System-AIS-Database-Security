-- ADMIN
USE AIS
------------------------------------------------------------------------------------------------------------------------------------------------------
															--ADD, VIEW, UPDATE STUDENT--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- a. Add student
EXEC dbo.sp_AddStudent
    @StudentLogin = 'S004',           -- Student ID
    @StudentPwd = 'Student4',		-- Temporary password
    @StudentName = 'Student4',        -- Student's name
    @StudentPhone = '012-4124552';    -- Student's phone number
GO


-- b. View Student (except password)
EXEC SP_Admin_ViewStudent


-- b. update student details except password (option1)
EXEC dbo.SP_AdminUpdateStudent
    @StudentLogin = 'S004',            -- Student ID
    @NewStudentName = 'Updated Student4',  -- New student name
    @NewStudentPhone = '012-5552222';  -- New student phone number
GO


-- update phone only (option2) 
EXEC SP_AdminUpdateStudent
    @StudentLogin = 'S004',            -- Student ID
    @NewStudentPhone = '012-55562366';  -- New student phone number
GO

------------------------------------------------------------------------------------------------------------------------------------------------------
															--ADD, VIEW, UPDATE LECTURER--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- a. Add lecturer
EXEC dbo.sp_AddLecturer
    @LecturerLogin = 'L003',
    @LecturerPwd = 'Temp123',
    @LecturerName = 'Lecturer3',
    @LecturerPhone = '018-9124812',
    @LecturerDept = 'Computer Science';
GO


-- b. View Lecturer
EXEC SP_Admin_ViewLecturer


-- b. Update Lecturer
EXEC SP_AdminUpdateLecturer
    @LecturerLogin = 'L003',            -- Lecturer's login ID
	@NewLecturerName = 'Lect3',
    @NewLecturerPhone = '011-666-7777',  -- New lecturer phone number
    @NewLecturerDept = 'Economics';       -- New lecturer department
GO


-- update Department only (option2)
EXEC SP_AdminUpdateLecturer
    @LecturerLogin = 'L005',            -- Lecturer's login ID
    @NewLecturerDept = 'Physics';       -- New lecturer department
GO


------------------------------------------------------------------------------------------------------------------------------------------------------
															--ADD, VIEW, UPDATE, DELETE SUBJECT--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- c. View subject
SELECT * FROM Subject;


-- c. Add Subject
EXEC SP_AddSubject 
    @Code = 'JAVA3', 
    @Title = 'Java Programming';
GO


-- c. Update Subject 
EXEC SP_AdminUpdateSubject
		@OldCode = 'DBS3',                    
        @NewCode = 'DBS4',
		@NewTitle = 'Database 3'
GO


-- c. Delete subject
EXEC SP_DeleteSubject
		@SubjectCode = 'DBS4'              
GO


------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------------------------------------
															--VIEW, DELETE RESULT--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- View result (Cannot View Grade Column)
SELECT * FROM Result 


-- View result (Can View without Grade Column)
OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO
SELECT 
    ID,                             -- Result Table ID (Auto-generated)
    StudentID,                      -- Student ID (Foreign Key from Student Table)
    CONVERT(VARCHAR(100), DECRYPTBYKEY(LecturerID)) AS DecryptedLecturerID,   -- Decrypted Lecturer ID
    SubjectCode,                    -- Subject Code (Foreign Key from Subject Table)
    AssessmentDate                  -- Date of Assessment
FROM 
    Result;
GO
CLOSE SYMMETRIC KEY LecturerIDKey;
GO


-- d. Delete Result
EXEC SP_DeleteResult
	@ResultID = '4'
GO

-- e. admin track deleted data
-- admin track deleted / modified subject data
EXEC SP_TrackSubjectData
GO
 
-- admin track deleted / modified result record
EXEC SP_TrackResultData
GO

-- f. admin recover selected deleted any data 
-- admin recover deleted / modified subject data
EXEC SP_RecoverSubjectData 
	@Code = 'DBS4', 
	@ValidFrom = '2024-09-17 14:10:03.6308390';
GO
 
-- admin recover result record
EXEC SP_RecoverResultByID 
	@ID = 4,
	@ExpectedValidTo = '2024-09-17 14:06:05.1411781';
GO


------------------------------------------------------------------------------------------------------------------------------------------------------
															--Steps that are NOT Allowed--
------------------------------------------------------------------------------------------------------------------------------------------------------
-- g. Cannot read or update lecturer/student password
SELECT * FROM Student
SELECT * FROM Lecturer

SELECT ID, Name, Phone AS Unmasked_Phone                      
FROM Student;    

OPEN SYMMETRIC KEY LecturerIDKey DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';
GO
SELECT 
    CONVERT(VARCHAR(100), DECRYPTBYKEY(ID)) AS DecryptedLecturerID,   
    Name,                    
    Phone AS Unmasked_Phone,                   
    Department              
FROM 
    Lecturer;
GO
CLOSE SYMMETRIC KEY LecturerIDKey;
GO


-- h. read, add or update student's result
-- Cannot View result
SELECT * FROM Result

-- Can View without result column only
SELECT 
    ID,                             -- Result Table ID (Auto-generated)
    StudentID,                      -- Student ID (Foreign Key from Student Table)
    CONVERT(VARCHAR(100), DECRYPTBYKEY(LecturerID)) AS DecryptedLecturerID,   -- Decrypted Lecturer ID
    SubjectCode,                    -- Subject Code (Foreign Key from Subject Table)
    AssessmentDate                  -- Date of Assessment
	-- Without Grade Column
FROM 
    Result;
GO

-- cannot update (Result Table is denied)
UPDATE Result
SET 
	Grade = 'B'
WHERE ID = 3;

-- cannot insert
OPEN SYMMETRIC KEY LecturerIDKey
DECRYPTION BY PASSWORD = 'LecturerIDEncryptionKey@456';  

DECLARE @EncryptedLecturerID VARBINARY(MAX);
SELECT @EncryptedLecturerID = ID
FROM Lecturer
WHERE CONVERT(VARCHAR(10), DECRYPTBYKEY(ID)) = 'L001';

INSERT INTO Result (StudentID, LecturerID, SubjectCode, AssessmentDate,Grade )
VALUES ('S001', @EncryptedLecturerID, 'ENG1', '2024-10-01','D');
CLOSE SYMMETRIC KEY LecturerIDKey;


-- i. drop any table
DROP TABLE Student;
DROP TABLE Result;
DROP TABLE Lecturer;
DROP TABLE Subject;

