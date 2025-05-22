IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'AirportReservationsDB')
BEGIN
    CREATE DATABASE AirportReservationsDB;
END
USE AirportReservationsDB;
-- Schema & sp_IssueTicket Supporting Multi‑Leg Itineraries
-- with Baggage, Meal & Preferred Seat Fees

-- ================================================
-- TABLE: Employee
-- ================================================
CREATE TABLE Employee
(
    EmployeeID INT PRIMARY KEY IDENTITY(1,1),
    FirstName VARCHAR(100) NOT NULL,
    LastName VARCHAR(100) NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    Username VARCHAR(50) NOT NULL UNIQUE,
    Password VARCHAR(255) NOT NULL,
   Role VARCHAR(30) NOT NULL CHECK (Role IN ('Ticketing Staff', 'Ticketing Supervisor'))
);

-- ================================================
-- TABLE: LoginActivity
-- ================================================
CREATE TABLE LoginActivity (
    LoginID INT PRIMARY KEY IDENTITY(1,1),
    EmployeeID INT NOT NULL,
    LoginTimestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    IsAuthenticated BIT NOT NULL,
    FOREIGN KEY(EmployeeID) REFERENCES Employee(EmployeeID) ON DELETE CASCADE
);

-- ================================================
-- TABLE: SupervisorIntervention
-- ================================================
CREATE TABLE SupervisorIntervention (
    InterventionID INT PRIMARY KEY IDENTITY(1,1),
    SupervisorID INT NOT NULL,
    EmployeeID INT NOT NULL,
    InterventionTime DATETIME DEFAULT CURRENT_TIMESTAMP,
    PermissionGranted BIT NOT NULL,
    FOREIGN KEY(SupervisorID) REFERENCES Employee(EmployeeID) ON DELETE NO ACTION,
    FOREIGN KEY(EmployeeID) REFERENCES Employee(EmployeeID) ON DELETE CASCADE
);

-- ================================================
-- TABLE: Passenger
-- ================================================
CREATE TABLE Passenger (
    PassengerID INT PRIMARY KEY IDENTITY(1,1),
    FirstName VARCHAR(100) NOT NULL,
    LastName VARCHAR(100) NOT NULL,
    Email VARCHAR(100) NOT NULL UNIQUE,
    DateOfBirth DATE NOT NULL,
    Gender VARCHAR(10) NOT NULL CHECK (Gender IN ('Male', 'Female', 'Other')),
    MealPreference VARCHAR(15) NOT NULL CHECK (MealPreference IN ('Vegetarian', 'Non-Vegetarian')),
    EmergencyContactNumber VARCHAR(15)
);

-- ================================================
-- TABLE: Flight
-- ================================================
CREATE TABLE Flight (
    FlightID INT PRIMARY KEY IDENTITY(1,1),
    FlightNumber VARCHAR(20) NOT NULL UNIQUE,
    DepartureTime DATETIME NOT NULL,
    ArrivalTime DATETIME NOT NULL,
    Origin VARCHAR(100) NOT NULL,
    Destination VARCHAR(100) NOT NULL,
    BaseFare DECIMAL(10,2) NOT NULL CHECK(BaseFare >= 0),
    SeatCapacity INT NOT NULL CHECK(SeatCapacity > 0),
    CHECK (ArrivalTime > DepartureTime)
);

-- ================================================
-- TABLE: Itinerary 
-- ================================================
CREATE TABLE Itinerary (
    ItineraryID INT PRIMARY KEY IDENTITY(1,1),
    PNR VARCHAR(10) NOT NULL UNIQUE,
    PassengerID INT NOT NULL,
    Status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK (Status IN ('Confirmed','Pending','Cancelled','Ticket Issued')),
    ReservationDate DATE NOT NULL,
    CONSTRAINT CHK_ReservationDate CHECK (ReservationDate >= CAST(GETDATE() AS DATE)),   -- QUESTION 2: Constraint to Check that Reservation Date is not in past.
    FOREIGN KEY(PassengerID) REFERENCES Passenger(PassengerID) ON DELETE NO ACTION
);
-- ================================================
-- TABLE: ItinerarySegment (one entry per flight leg)
-- Enforce unique seat per flight
-- ================================================
CREATE TABLE ItinerarySegment (
    ItineraryID INT NOT NULL,
    SegmentNumber INT NOT NULL,
    FlightID INT NOT NULL,
    SeatNumber VARCHAR(5),
    SeatClass VARCHAR(10) NOT NULL DEFAULT 'Economy' CHECK (SeatClass IN ('Economy','Business','FirstClass')),
    SeatStatus VARCHAR(10) NOT NULL DEFAULT 'Available' CHECK (SeatStatus IN ('Available', 'Reserved')),
    PRIMARY KEY(ItineraryID,SegmentNumber),
    UNIQUE(FlightID,SeatNumber),
    FOREIGN KEY(ItineraryID) REFERENCES Itinerary(ItineraryID) ON DELETE CASCADE,
    FOREIGN KEY(FlightID) REFERENCES Flight(FlightID) ON DELETE NO ACTION
);
-- ================================================
-- TABLE: ServiceRates (only required services)
-- ================================================
CREATE TABLE ServiceRates (
    ServiceRateID INT PRIMARY KEY IDENTITY(1,1),
    ServiceType VARCHAR(20) NOT NULL CHECK (ServiceType IN ('Extra Baggage','Upgraded Meal','Preferred Seat')),
    ServiceFee DECIMAL(10,2) NOT NULL CHECK(ServiceFee > 0)
);
-- ================================================
-- TABLE: ItineraryServices (services added to an itinerary)
-- ================================================
CREATE TABLE ItineraryServices (
    ItineraryServiceID INT PRIMARY KEY IDENTITY(1,1),
    ItineraryID INT NOT NULL,
    ServiceRateID INT NOT NULL,
    FOREIGN KEY(ItineraryID) REFERENCES Itinerary(ItineraryID) ON DELETE CASCADE,
    FOREIGN KEY(ServiceRateID) REFERENCES ServiceRates(ServiceRateID) ON DELETE NO ACTION,
    UNIQUE(ItineraryID,ServiceRateID)
);

CREATE INDEX idx_itinerary_services_itinerary_id ON ItineraryServices(ItineraryID);

-- ================================================
-- TABLE: Baggage (linked to Itinerary)
-- ================================================
CREATE TABLE Baggage (
    BaggageID INT PRIMARY KEY IDENTITY(1,1),
    ItineraryID INT NOT NULL,
    BaggageWeight DECIMAL(10,2) NOT NULL CHECK(BaggageWeight >= 0),
    BaggageStatus VARCHAR(10) NOT NULL DEFAULT 'CheckedIn',
    CONSTRAINT CHK_BaggageStatus CHECK(BaggageStatus IN ('CheckedIn', 'Loaded')),
    FOREIGN KEY(ItineraryID) REFERENCES Itinerary(ItineraryID) ON DELETE CASCADE
);

-- ================================================
-- TABLE: Ticket (references Itinerary)
-- ================================================
CREATE TABLE Ticket (
    TicketID INT PRIMARY KEY IDENTITY(1,1),
    ItineraryID INT NOT NULL,
    eBoardingNumber VARCHAR(50) NOT NULL UNIQUE,
    IssuedByEmployeeID INT,
    IssueTimestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    Fare DECIMAL(10,2) NOT NULL CHECK(Fare >= 0),
    FOREIGN KEY(ItineraryID) REFERENCES Itinerary(ItineraryID) ON DELETE CASCADE,
    FOREIGN KEY(IssuedByEmployeeID) REFERENCES Employee(EmployeeID) ON DELETE SET NULL,
    INDEX idx_ticket_itinerary_id (ItineraryID)
);
GO
/*
The authentication system implements three critical security components:
  1) EMPLOYEE REGISTRATION with strong password validation (12+ chars, uppercase, 
  symbols, numbers) and contextual checks (no username/name in password), plus
  secure salted hash storage (SHA-256) to protect credentials.
  */
  
-- ================================
-- PROCEDURE: sp_RegisterEmployee
-- ================================

-- Purpose: Register a new employee with password validation
GO
CREATE PROCEDURE sp_RegisterEmployee (
    @p_FirstName VARCHAR(100),
    @p_LastName VARCHAR(100),
    @p_Email VARCHAR(100),
    @p_Username VARCHAR(50),
    @p_Password VARCHAR(255),
    @p_Role VARCHAR(50)  -- Changed from ENUM to VARCHAR
)
AS
BEGIN
    DECLARE @v_HashedPassword VARCHAR(255); -- Increased length for salt+hash
    DECLARE @v_Salt VARCHAR(32);
    DECLARE @v_Length INT;
    DECLARE @v_UserExists INT = 0;
    DECLARE @ErrorMsg NVARCHAR(200);
    
    -- Validate that Role is one of the allowed values
    IF @p_Role NOT IN ('Ticketing Staff', 'Ticketing Supervisor')
    BEGIN
        THROW 50000, 'Role must be either ''Ticketing Staff'' or ''Ticketing Supervisor''.', 1;
        RETURN;
    END;
    
    -- Check if user already exists
    SELECT @v_UserExists = COUNT(*) 
    FROM Employee 
    WHERE Username = @p_Username OR Email = @p_Email;
    
    IF @v_UserExists > 0
    BEGIN
        THROW 50000, 'Employee with this username or email already exists.', 1;
        RETURN;
    END;
    
    -- Password validation checks
    -- Step 1: Check minimum length requirement
    SET @v_Length = LEN(@p_Password);
    IF @v_Length < 12
    BEGIN
        THROW 50000, 'Password must be at least 12 characters long.', 1;
        RETURN;
    END;
    
    -- Step 2: Check for uppercase letter requirement
    IF @p_Password NOT LIKE '%[A-Z]%'
    BEGIN
        THROW 50000, 'Password must contain at least one uppercase letter.', 1;
        RETURN;
    END;
    
    -- Step 3: Check for special character requirement
    IF @p_Password NOT LIKE '%[^a-zA-Z0-9]%'
    BEGIN
        THROW 50000, 'Password must contain at least one symbol.', 1;
        RETURN;
    END;
    
    -- Step 4: Check for number requirement
    IF @p_Password NOT LIKE '%[0-9]%'
    BEGIN
        THROW 50000, 'Password must contain at least one number.', 1;
        RETURN;
    END;
    
    -- Step 5: Security check - password shouldn't contain username
    IF LOWER(@p_Password) LIKE '%' + LOWER(@p_Username) + '%'
    BEGIN
        THROW 50000, 'Password must not contain your username.', 1;
        RETURN;
    END;
    
    -- Step 6: Additional check - password shouldn't contain firstname or lastname
    IF LOWER(@p_Password) LIKE '%' + LOWER(@p_FirstName) + '%' OR 
       LOWER(@p_Password) LIKE '%' + LOWER(@p_LastName) + '%'
    BEGIN
        THROW 50000, 'Password must not contain your first name or last name.', 1;
        RETURN;
    END;
    
    -- Generate a random salt
    SET @v_Salt = CONVERT(VARCHAR(32), HASHBYTES('MD5', CAST(NEWID() AS VARCHAR(36))), 2);
    
    -- Hash the password using SHA2 (256-bit) with the salt
    SET @v_HashedPassword = @v_Salt + ':' + CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', 
                           CAST(@v_Salt + @p_Password AS NVARCHAR(MAX))), 2);
    
    -- Insert into Employee table
    INSERT INTO Employee (FirstName, LastName, Email, Username, Password, Role)
    VALUES (@p_FirstName, @p_LastName, @p_Email, @p_Username, @v_HashedPassword, @p_Role);
END;
GO
-- Inserting new employees into the database with roles as Ticketing Staff or Ticketing Supervisor
BEGIN
    EXEC sp_RegisterEmployee 'James', 'Smith', 'james.smith@gulfair.com', 'jsmith', 'Pass1234@Secure', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Maria', 'Rodriguez', 'maria.r@gulfair.com', 'mrodriguez', 'Secure@456!System', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Robert', 'Johnson', 'robert.j@gulfair.com', 'rjohnson', 'Pwd789#Safe123', 'Ticketing Supervisor'; -- Supervisor 1
    EXEC sp_RegisterEmployee 'Susan', 'Williams', 'susan.w@gulfair.com', 'swilliams', 'Safe@pass1234!', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'David', 'Brown', 'david.b@gulfair.com', 'dbrown', 'srilekha!1234Secure', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Linda', 'Davis', 'linda.d@gulfair.com', 'ldavis', 'amma@Pass1234!#', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Michael', 'Miller', 'michael.m@agulfair.com', 'mmiller', 'MikePass#2024#Service', 'Ticketing Supervisor'; -- Supervisor 2
    EXEC sp_RegisterEmployee 'Frank', 'Moore', 'frank.m@gulfair.com', 'fmoore', 'jibbili@1234!Access', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Grace', 'Hall', 'grace.hall@gulfair.com', 'graceh', 'umma@Hnjnll2024Secure', 'Ticketing Staff';
    EXEC sp_RegisterEmployee 'Henry', 'Ford', 'henry.ford@gulfair.com', 'henryf', 'wa#sajnsjand123!Login', 'Ticketing Staff';
	EXEC sp_RegisterEmployee 'Casa', 'Blanca', 'casa.b@gulfair.com', 'casab', 'casa123hufwu', 'Ticketing Staff'; --Will Throw An Error Because of Password
END;

-- Display Rows From Employee Table
SELECT*FROM Employee;
/*
The authentication system implements three critical security components:
  2. SECURE LOGIN PROCESS that extracts salt from stored password, rehashes input 
  with the same salt, compares only hash portions, and logs all authentication
  attempts without exposing sensitive data.
  */
-- ================================
-- PROCEDURE: sp_EmployeeLogin 
-- ================================
-- Purpose: Authenticate employee login and log the attempt
GO
CREATE PROCEDURE sp_EmployeeLogin (
    @p_Username VARCHAR(50),
    @p_Password VARCHAR(255),
    @p_IsAuthenticated BIT OUTPUT,
    @p_EmployeeID INT OUTPUT
)
AS
BEGIN
    DECLARE @v_EmployeeID INT = NULL;
    DECLARE @v_StoredPassword VARCHAR(255);
    DECLARE @v_Salt VARCHAR(32);
    DECLARE @v_HashedPart VARCHAR(64);
    DECLARE @v_HashedInputPassword VARCHAR(64);
    DECLARE @not_found BIT = 0;
    
    -- Step 1: Retrieve employee ID and stored password (salt+hash) from DB
    SELECT @v_EmployeeID = EmployeeID, @v_StoredPassword = Password
    FROM Employee
    WHERE Username = @p_Username;
    
    -- Check if employee was found
    IF @@ROWCOUNT = 0
        SET @not_found = 1;
    
    -- Step 2: Extract salt from stored password
    IF @not_found = 0
    BEGIN
        SET @v_Salt = SUBSTRING(@v_StoredPassword, 1, CHARINDEX(':', @v_StoredPassword) - 1);
        SET @v_HashedPart = SUBSTRING(@v_StoredPassword, CHARINDEX(':', @v_StoredPassword) + 1, LEN(@v_StoredPassword));
        
        -- Step 3: Hash the input password with the retrieved salt
        -- Convert the salt and password to the appropriate type and hash them
        SET @v_HashedInputPassword = CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', 
                                   CAST(@v_Salt + @p_Password AS NVARCHAR(MAX))), 2);
        
        -- Step 4: Authenticate by comparing only the hash part
        IF @v_HashedPart = @v_HashedInputPassword
        BEGIN
            -- Match
            SET @p_IsAuthenticated = 1;
            SET @p_EmployeeID = @v_EmployeeID;
        END
        ELSE
        BEGIN
            -- Password mismatch
            SET @p_IsAuthenticated = 0;
            SET @p_EmployeeID = @v_EmployeeID;
        END
    END
    ELSE
    BEGIN
        -- No such username
        SET @p_IsAuthenticated = 0;
        SET @p_EmployeeID = NULL;
    END
    
    -- Step 5: Log login attempt (only if user exists)
    IF @not_found = 0
    BEGIN
        INSERT INTO LoginActivity (EmployeeID, IsAuthenticated)
        VALUES (@v_EmployeeID, @p_IsAuthenticated);
    END
END;
GO
-- Purpose: To Check Authentication of employee login and log the attempt

-- Declare variables 
DECLARE @is_authenticated BIT = 0;
DECLARE @employee_id INT = NULL;

-- First employee with correct credentials
EXEC sp_EmployeeLogin 
    @p_Username = 'jsmith', 
    @p_Password = 'Pass1234@Secure', 
    @p_IsAuthenticated = @is_authenticated OUTPUT, 
    @p_EmployeeID = @employee_id OUTPUT;

-- Display first result
SELECT 'James Smith' AS Employee_Name, @is_authenticated AS Authentication_Status, @employee_id AS Employee_ID;

-- Second employee with incorrect password
EXEC sp_EmployeeLogin 
    @p_Username = 'mrodriguez', 
    @p_Password = 'WrongPassword123', 
    @p_IsAuthenticated = @is_authenticated OUTPUT, 
    @p_EmployeeID = @employee_id OUTPUT;

-- Display second result
SELECT 'Maria Rodriguez' AS Employee_Name, @is_authenticated AS Authentication_Status, @employee_id AS Employee_ID;

/*
The authentication system implements three critical security components:  
3. ROLE-BASED ACCESS CONTROL allowing only supervisors to grant special access
  permissions, with verification of both requestor's role and target employee's
  existence, maintaining a complete audit trail of interventions.
*/
-- ================================
-- PROCEDURE: sp_GrantAccessBySupervisor
-- ================================
GO
CREATE PROCEDURE sp_GrantAccessBySupervisor (
    @p_SupervisorID INT,
    @p_EmployeeID INT,
    @p_Granted BIT
)
AS
BEGIN
    -- Validate supervisor role and employee existence in one query
    IF NOT EXISTS (
        SELECT 1 FROM Employee WHERE EmployeeID = @p_SupervisorID AND Role = 'Ticketing Supervisor'
    )
    BEGIN
        THROW 50000, 'Access denied: Invalid supervisor or insufficient privileges.', 1;
    END
    ELSE IF NOT EXISTS (
        SELECT 1 FROM Employee WHERE EmployeeID = @p_EmployeeID
    )
    BEGIN
        THROW 50000, 'Employee ID not found.', 1;
    END
    ELSE
    BEGIN
        -- Record the supervisor intervention
        INSERT INTO SupervisorIntervention (SupervisorID, EmployeeID, PermissionGranted)
        VALUES (@p_SupervisorID, @p_EmployeeID, @p_Granted);
    END
END;
GO
-- Execute the procedure
EXEC sp_GrantAccessBySupervisor 3, 4, 1;   -- Granting access to EmployeeID 4
EXEC sp_GrantAccessBySupervisor 3, 5, 0;   -- Denying access to EmployeeID 5

-- ================================
-- Purpose: View all recorded supervisor interventions
-- ================================
SELECT 
    si.InterventionID,
    s.FirstName + ' ' + s.LastName AS Supervisor,
    e.FirstName + ' ' + e.LastName AS Employee,
    si.InterventionTime,
    CASE WHEN si.PermissionGranted = 1 THEN 'Granted' ELSE 'Denied' END AS Status
FROM 
    SupervisorIntervention si
    JOIN Employee s ON si.SupervisorID = s.EmployeeID
    JOIN Employee e ON si.EmployeeID = e.EmployeeID
ORDER BY 
    si.InterventionTime DESC;
-- ========================================
-- Create the Remaining Tables
-- ========================================
-- PASSENGERS
-- ========================================
INSERT INTO Passenger (
    FirstName,
    LastName,
    Email,
    DateOfBirth,
    MealPreference,
    EmergencyContactNumber,
    Gender
) VALUES
  ('John',    'Smith',    'john.smith@email.com',   '1975-05-12', 'Vegetarian',     '123-456-7890', 'Male'),
  ('Mary',    'Smithson',  'mary.s@email.com',       '1980-10-25', 'Non-Vegetarian', '234-567-8901', 'Female'),
  ('Robert',  'Williams', 'robert.w@email.com',     '1990-03-15', 'Vegetarian',     '345-678-9012', 'Male'),
  ('Sarah',   'Brown',    'sarah.b@email.com',      '1995-07-08', 'Vegetarian',     '456-789-0123', 'Female'),
  ('Michael', 'Davis',    'michael.d@email.com',    '1985-12-03', 'Non-Vegetarian', '567-890-1234', 'Male'),
  ('Jennifer','Wilson',   'jennifer.w@email.com',   '1992-09-22', 'Vegetarian',     '678-901-2345', 'Female'),
  ('David',   'Taylor',   'david.t@email.com',      '1970-11-18', 'Non-Vegetarian', '789-012-3456', 'Male'),
  ('Lisa',    'Anderson', 'lisa.a@email.com',       '1988-02-14', 'Vegetarian',     '890-123-4567', 'Female'),
  ('Thomas',  'Garcia',   'thomas.g@email.com',     '1998-06-30', 'Non-Vegetarian', '901-234-5678', 'Male'),
  ('Rachel',  'Nguyen',   'rachel.n@email.com',     '1985-03-14', 'Vegetarian',     '812-345-6789', 'Female'),
  ('Leo',     'Martinez', 'leo.m@email.com',        '1979-12-22', 'Non-Vegetarian', '723-456-7890', 'Male'),
  ('Aisha',   'Khan',     'aisha.k@email.com',      '1992-08-10', 'Vegetarian',     '934-567-8901', 'Female'),
  ('Daniel',  'Lee',      'daniel.l@email.com',     '2001-04-02', 'Non-Vegetarian', '845-678-9012', 'Male'),
  ('Vaamika', 'Bharath',  'v.bharath@email.com',    '2004-10-04', 'Vegetarian',     '994-054-3506', 'Female');
  
-- ========================================
-- FLIGHT
-- ========================================
INSERT INTO Flight (
    FlightNumber,
    DepartureTime,
    ArrivalTime,
    Origin,
    Destination,
    BaseFare,
    SeatCapacity
) VALUES
  ('BA456', '2025-05-01 08:30:00', '2025-05-01 10:45:00', 'London',     'Paris',      150.00, 180),
  ('BA789', '2025-05-01 12:15:00', '2025-05-01 15:30:00', 'Paris',      'Rome',       220.00, 160),
  ('BA234', '2025-05-02 09:00:00', '2025-05-02 11:15:00', 'London',     'Amsterdam',  135.00, 170),
  ('BA567', '2025-05-02 14:45:00', '2025-05-02 18:00:00', 'Amsterdam',  'Berlin',     180.00, 150),
  ('BA890', '2025-05-03 07:30:00', '2025-05-03 12:45:00', 'London',     'Barcelona',  210.00, 175),
  ('BA123', '2025-05-03 16:00:00', '2025-05-03 20:15:00', 'Barcelona',  'Rome',       195.00, 165),
  ('BA345', '2025-05-04 10:30:00', '2025-05-04 14:00:00', 'London',     'Munich',     185.00, 155),
  ('BA678', '2025-05-04 17:15:00', '2025-05-04 21:30:00', 'Munich',     'Athens',     250.00, 145),
  ('BA901', '2025-05-05 08:45:00', '2025-05-05 10:30:00', 'London',     'Dublin',     120.00, 185),
  ('BA924', '2025-05-06 15:00:00', '2025-05-06 19:15:00', 'Dublin',     'Lisbon',     230.00, 160);

-- ========================================
-- ServiceRates
-- ========================================
INSERT INTO ServiceRates (ServiceType, ServiceFee) VALUES
  ('Extra Baggage', 100.00),
  ('Upgraded Meal', 20.00),
  ('Preferred Seat', 30.00);
  
-- ========================================
-- Itinerary
-- ========================================
INSERT INTO Itinerary (PNR, PassengerID, Status, ReservationDate) VALUES
  ('ABC123',  1, 'Pending', '2025-09-10'),
  ('DEF456',  2, 'Pending', '2025-08-11'),
  ('GHI789',  3, 'Confirmed', '2025-07-12'),
  ('JKL012',  4, 'Confirmed', '2025-06-13'),
  ('MNO345',  5, 'Confirmed', '2025-05-14'),
  ('PQR678',  6, 'Confirmed', '2025-05-15'),
  ('STU901',  7, 'Confirmed', '2025-08-16'),
  ('VWX234',  8, 'Confirmed', '2025-06-17'),
  ('YZA567',  9, 'Confirmed', '2025-05-28'),
  ('BCD890', 10, 'Cancelled', '2025-05-29'),
  ('BJJ696', 14, 'Confirmed', CAST(GETDATE() AS DATE));
  

-- ========================================
-- ItinerarySegment
-- ========================================
INSERT INTO ItinerarySegment (ItineraryID, SegmentNumber, FlightID, SeatNumber, SeatClass, SeatStatus)
VALUES 
(1, 1, 1, '12A', 'Economy', 'Available'),
(2, 1, 3, '15B', 'Economy', 'Available'),
(3, 1, 5, '18C', 'Economy', 'Available'),
(4, 1, 7, '21D', 'Business', 'Available'),
(5, 1, 9, '24E', 'Economy', 'Available'),
(6, 1, 1, '13F', 'Economy', 'Available'),
(6, 2, 2, '14G', 'Economy', 'Available'),
(7, 1, 3, '16H', 'Business', 'Available'),
(7, 2, 4, '17I', 'Business', 'Available'),
(8, 1, 5, '19J', 'Economy', 'Available'),
(8, 2, 6, '20K', 'Economy', 'Available'),
(9, 1, 7, '22L', 'FirstClass', 'Available'),
(9, 2, 8, '23M', 'FirstClass', 'Available'),
(10, 1, 9, '25N', 'Economy', 'Available'),
(10, 2, 10, '26O', 'Economy', 'Available'),
(11, 1, 1, '16B', 'Business', 'Available');
  
-- ========================================
-- Baggage
-- ========================================
INSERT INTO Baggage (ItineraryID, BaggageWeight, BaggageStatus) VALUES
  (1,  18.5, 'CheckedIn'),
  (2,  22.3, 'CheckedIn'),
  (3,  25.7, 'CheckedIn'),
  (4,  30.0, 'Loaded'),
  (5,  15.5, 'Loaded'),
  (6,  28.4, 'CheckedIn'),
  (7,  35.2, 'CheckedIn'),
  (8,  19.8, 'CheckedIn'),
  (9,  42.5, 'CheckedIn'),
  (10, 21.1, 'CheckedIn'),
  (11, 30.1, 'Loaded');

-- ========================================
-- ItineraryServices
-- ========================================
INSERT INTO ItineraryServices (ItineraryID, ServiceRateID) VALUES
  (1, 2), (4, 2), (6, 2), (9, 2),
  (2, 3), (3, 3), (7, 3), (10, 3),
  (4, 3), (9, 3),(11,2);

/*
The ticket issuance procedure implements three critical business processes:

1. TRANSACTION INTEGRITY using row-level locking and validation to ensure 
  itineraries are confirmed and seat capacity is available before proceeding,
  preventing overbooking situations.

2. COMPREHENSIVE FARE CALCULATION that aggregates base fare with additional 
  service fees (baggage, meals, preferred seating) in an efficient manner,
  producing an accurate total fare for each ticket.
  
3. ATOMIC OPERATION guaranteeing that ticket creation, e-boarding pass generation
  with timestamped unique identifier, and itinerary status update occur as a
  single transaction that either completely succeeds or completely fails.
*/
-- ================================
-- PROCEDURE: sp_IssueTicket
-- ================================
GO
CREATE PROCEDURE sp_IssueTicket
    @PNR VARCHAR(10),
    @EmployeeID INT
AS
BEGIN
    DECLARE @ItineraryID INT;
    DECLARE @Status VARCHAR(20);
    DECLARE @BaseFare DECIMAL(10,2) = 0;
    DECLARE @Weight DECIMAL(10,2) = 0;
    DECLARE @BaggageFee DECIMAL(10,2) = 0;
    DECLARE @MealFee DECIMAL(10,2) = 0;
    DECLARE @PrefSeatFee DECIMAL(10,2) = 0;
    DECLARE @TotalFare DECIMAL(10,2);
    DECLARE @eBoarding VARCHAR(50);
    DECLARE @TicketID INT;

    BEGIN TRANSACTION;

    -- Step 1: Lock and validate itinerary
    SELECT @ItineraryID = ItineraryID, @Status = Status
    FROM Itinerary WITH (UPDLOCK)
    WHERE PNR = @PNR;

    IF @ItineraryID IS NULL
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50001, 'Itinerary not found.', 1;
    END

    IF @Status != 'Confirmed'
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50002, 'Itinerary not confirmed.', 1;
    END
    -- Step 2: Check seat capacity
    IF EXISTS (
        SELECT 1
        FROM ItinerarySegment s
        JOIN Flight f ON s.FlightID = f.FlightID
        LEFT JOIN (
            SELECT s2.FlightID, COUNT(*) AS booked
            FROM Ticket t2
            JOIN Itinerary i2 ON t2.ItineraryID = i2.ItineraryID
            JOIN ItinerarySegment s2 ON i2.ItineraryID = s2.ItineraryID
            WHERE i2.Status = 'Ticket Issued'
            GROUP BY s2.FlightID
        ) b ON b.FlightID = s.FlightID
        WHERE s.ItineraryID = @ItineraryID AND (ISNULL(b.booked, 0) + 1) > f.SeatCapacity
    )
    BEGIN
        ROLLBACK TRANSACTION;
        THROW 50003, 'No seats available on one or more flights.', 1;
    END

    -- Step 3: Calculate base fare
    SELECT @BaseFare = ISNULL(SUM(f.BaseFare), 0)
    FROM ItinerarySegment s
    JOIN Flight f ON s.FlightID = f.FlightID
    WHERE s.ItineraryID = @ItineraryID;

    -- Baggage fee
    SELECT @Weight = ISNULL(SUM(BaggageWeight), 0) - 20
    FROM Baggage WHERE ItineraryID = @ItineraryID;

    IF @Weight < 0 SET @Weight = 0;

    SELECT @BaggageFee = ISNULL(@Weight * ServiceFee, 0)
    FROM ServiceRates WHERE ServiceType = 'Extra Baggage';

    -- Meal fee
    SELECT @MealFee = ISNULL(SUM(sr.ServiceFee), 0)
    FROM ItineraryServices iserv
    JOIN ServiceRates sr ON iserv.ServiceRateID = sr.ServiceRateID
    WHERE iserv.ItineraryID = @ItineraryID AND sr.ServiceType = 'Upgraded Meal';

    -- Preferred seat fee
    SELECT @PrefSeatFee = ISNULL(SUM(sr.ServiceFee), 0)
    FROM ItineraryServices iserv
    JOIN ServiceRates sr ON iserv.ServiceRateID = sr.ServiceRateID
    WHERE iserv.ItineraryID = @ItineraryID AND sr.ServiceType = 'Preferred Seat';

    -- Calculate total fare
    SET @TotalFare = @BaseFare + @BaggageFee + @MealFee + @PrefSeatFee;

    -- Step 4: Update itinerary status
    UPDATE Itinerary SET Status = 'Ticket Issued' WHERE ItineraryID = @ItineraryID;

    -- Step 5: Insert ticket
    SET @eBoarding = 'EB-' + FORMAT(GETDATE(), 'yyyyMMddHHmm') + '-' + CAST(@ItineraryID AS VARCHAR);
    
    INSERT INTO Ticket (ItineraryID, eBoardingNumber, IssuedByEmployeeID, Fare)
    VALUES (@ItineraryID, @eBoarding, @EmployeeID, @TotalFare);

    COMMIT TRANSACTION;
END;
GO
-- 2 Tickets issued by Employee ID 1
EXEC sp_IssueTicket 'JKL012', 1;
EXEC sp_IssueTicket 'MNO345', 1;
-- 3 Tickets issued by Employee ID 2
-- To Check Our Logic of Multi-Leg Itinerary
EXEC sp_IssueTicket 'PQR678', 2;
EXEC sp_IssueTicket 'STU901', 2;
EXEC sp_IssueTicket 'VWX234', 2;

-- 1 Tickets issued by Employee ID 5
EXEC sp_IssueTicket 'YZA567', 5;

--Condition to Check when Itinerary is Pending or Cancelled
EXEC sp_IssueTicket 'ABC123',4
EXEC sp_issueTicket 'BCD890',6

-- VIEW: Create a view for TicketDetails
GO
CREATE VIEW dbo.TicketDetails AS
SELECT
    t.TicketID AS TicketNumber,
    p.FirstName + ' ' + p.LastName AS PassengerName,
    f.FlightNumber,
    f.Origin,
    f.Destination,
    f.DepartureTime AS ValidFrom,
    f.ArrivalTime AS ValidTo,
    t.eBoardingNumber,
    t.Fare,
    t.IssueTimestamp
FROM Ticket t
JOIN Itinerary i ON t.ItineraryID = i.ItineraryID
JOIN Passenger p ON i.PassengerID = p.PassengerID
JOIN ItinerarySegment seg ON seg.ItineraryID = i.ItineraryID
JOIN Flight f ON seg.FlightID = f.FlightID;
GO
-- Display Ticket Details
SELECT*FROM TicketDetails;

-- ------------------------------------------------------------------------TASK-1 QUESTIONS------------------------------------------------------------------------

-- QUESTION 2 : TO CHECK THE check_reservation_date  
INSERT INTO Itinerary (PNR, PassengerID, Status, ReservationDate)
VALUES ('JJJ006', 1, 'Pending', '2023-09-10');

-- QUESTION 3: Identify Passengers with Pending Reservations and Passengers with age more than 40 years.
GO
CREATE PROCEDURE GetPendingAndOver40Passengers
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        p.PassengerID, 
        p.FirstName, 
        p.LastName, 
        DATEDIFF(YEAR, p.DateOfBirth, GETDATE()) AS Age,
        i.Status
    FROM Passenger p
    JOIN Itinerary i ON p.PassengerID = i.PassengerID
    WHERE i.Status = 'Pending'
      AND DATEDIFF(YEAR, p.DateOfBirth, GETDATE()) > 40;
END
GO
EXEC GetPendingAndOver40Passengers;

-- QUESTION 4a): To Search the Database by Passenger's last name and returns the results sorted by the most recent reservation date.
GO
CREATE PROCEDURE SearchByLastName
    @lastNameSearch VARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        i.PNR,
        p.FirstName,
        p.LastName,
        i.ReservationDate,
        i.Status,

        -- SeatNumbers
        STUFF((
            SELECT DISTINCT ', ' + ISNULL(seg2.SeatNumber, '')
            FROM ItinerarySegment seg2
            WHERE seg2.ItineraryID = i.ItineraryID
            FOR XML PATH(''), TYPE
        ).value('.', 'NVARCHAR(MAX)'), 1, 2, '') AS SeatNumbers,

        -- SeatClasses
        STUFF((
            SELECT DISTINCT ', ' + ISNULL(seg3.SeatClass, '')
            FROM ItinerarySegment seg3
            WHERE seg3.ItineraryID = i.ItineraryID
            FOR XML PATH(''), TYPE
        ).value('.', 'NVARCHAR(MAX)'), 1, 2, '') AS SeatClasses

    FROM 
        Itinerary i
    JOIN 
        Passenger p ON p.PassengerID = i.PassengerID
    WHERE 
        p.LastName LIKE '%' + @lastNameSearch + '%'
    ORDER BY 
        i.ReservationDate DESC;
END
GO
EXEC SearchByLastName 'Smith';

-- QUESTION 4b): Get Passengers with Specific Meal Requirement in Business Class for Today's Reservations
GO
CREATE PROCEDURE GetBusinessClassMealsForToday
AS
BEGIN
    SET NOCOUNT ON;

    SELECT 
        p.FirstName,
        p.LastName,
        p.MealPreference,
        i.PNR,
        i.ReservationDate,
        i1.SeatClass
    FROM 
        Itinerary i
    JOIN 
        Passenger p ON i.PassengerID = p.PassengerID
    JOIN 
        ItinerarySegment i1 ON i.ItineraryID = i1.ItineraryID
    WHERE 
        i1.SeatClass = 'Business'  -- Filter for Business Class
        AND CAST(i.ReservationDate AS DATE) = CAST(GETDATE() AS DATE);  -- Only today's reservations
END;
GO
EXEC GetBusinessClassMealsForToday;

-- QUESTION 4c): INSERT NEW EMPLOYEE
EXEC sp_RegisterEmployee 
    @p_FirstName = 'Bharath', 
    @p_LastName = 'Kumar', 
    @p_Email = 'b.k@gulfair.com', 
    @p_Username = 'bkumar', 
    @p_Password = 'Srilekha@@@11', 
    @p_Role = 'Ticketing Staff';

-- DISPLAY EMPLOYEE TABLE
SELECT*FROM EMPLOYEE;

-- Logic for checking passengers that has booked a flight before
SELECT 
    p.Email, 
    p.FirstName, 
    p.LastName,
    COUNT(i.ItineraryID) AS TotalBookings
FROM 
    Passenger p
JOIN 
    Itinerary i ON p.PassengerID = i.PassengerID
GROUP BY 
    p.Email, p.FirstName, p.LastName
HAVING 
    COUNT(i.ItineraryID) > 0;

-- QUESTION 4d): Update the details for a passenger that has booked a flight before.
GO
CREATE PROCEDURE UpdatePassengerByEmail
    @FirstName NVARCHAR(100),
    @LastName NVARCHAR(100),
    @Email NVARCHAR(100),
    @DOB DATE,
    @MealPreference NVARCHAR(20), -- Simulate ENUM with validation in app or trigger
    @EmergencyContact NVARCHAR(15),
    @Gender NVARCHAR(10)          -- Simulate ENUM
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @PassengerID INT;

    -- Get the PassengerID
    SELECT @PassengerID = PassengerID
    FROM Passenger
    WHERE Email = @Email;

    -- Check if passenger exists
    IF @PassengerID IS NULL
    BEGIN
        THROW 50000, 'Passenger with the given email does not exist', 1;
    END

    -- Check for at least one itinerary
    IF NOT EXISTS (
        SELECT 1 FROM Itinerary WHERE PassengerID = @PassengerID
    )
    BEGIN
        THROW 50000, 'Passenger has no itineraries', 1;
    END

    -- Perform the update
    UPDATE Passenger
    SET 
        FirstName = @FirstName,
        LastName = @LastName,
        DateOfBirth = @DOB,
        MealPreference = @MealPreference,
        EmergencyContactNumber = @EmergencyContact,
        Gender = @Gender
    WHERE PassengerID = @PassengerID;

    -- Return the updated passenger
    SELECT * FROM Passenger WHERE PassengerID = @PassengerID;
END;
GO

EXEC UpdatePassengerByEmail
    'Jennifer',
    'Wilson',
    'jennifer.w@email.com',
    '1992-09-22',
    'Vegetarian',
    '678-901-2345',
    'Female';

-- QUESTION 5): Employee Flight Revenue and E-Boarding Details
GO
CREATE VIEW EmployeeFlightRevenueView AS
WITH SegmentBase AS (
    SELECT 
        iseg.ItineraryID,
        iseg.FlightID,
        f.BaseFare AS SegmentBaseFare,
        COUNT(*) OVER (PARTITION BY iseg.ItineraryID) AS TotalSegments
    FROM 
        ItinerarySegment iseg
        JOIN Flight f ON iseg.FlightID = f.FlightID
),
BaggageFees AS (
    SELECT 
        b.ItineraryID,
        CASE 
            WHEN SUM(b.BaggageWeight) - 20 > 0 THEN (SUM(b.BaggageWeight) - 20) * sr.ServiceFee
            ELSE 0 
        END AS TotalBaggageFees
    FROM 
        Baggage b
        JOIN ServiceRates sr ON sr.ServiceType = 'Extra Baggage'
    GROUP BY b.ItineraryID, sr.ServiceFee
),
MealFees AS (
    SELECT 
        iserv.ItineraryID,
        SUM(CASE WHEN sr.ServiceType = 'Upgraded Meal' THEN sr.ServiceFee ELSE 0 END) AS TotalMealFees,
        SUM(CASE WHEN sr.ServiceType = 'Preferred Seat' THEN sr.ServiceFee ELSE 0 END) AS TotalSeatFees
    FROM 
        ItineraryServices iserv
        JOIN ServiceRates sr ON iserv.ServiceRateID = sr.ServiceRateID
    GROUP BY iserv.ItineraryID
)
SELECT 
    e.EmployeeID,
    CONCAT(e.FirstName, ' ', e.LastName) AS EmployeeName,
    t.eBoardingNumber,
    f.FlightNumber,
    f.Origin,
    f.Destination,
    i.PNR,
    sb.SegmentBaseFare,
    ROUND(COALESCE(bf.TotalBaggageFees, 0) / sb.TotalSegments, 2) AS SegmentBaggageFees,
    ROUND(COALESCE(mf.TotalMealFees, 0) / sb.TotalSegments, 2) AS SegmentMealFees,
    ROUND(COALESCE(mf.TotalSeatFees, 0) / sb.TotalSegments, 2) AS SegmentSeatFees,
    ROUND(t.Fare / sb.TotalSegments, 2) AS SegmentRevenue,
    ROUND(t.Fare, 2) AS FullTicketFare,
    sb.TotalSegments AS FlightSegments
FROM 
    Ticket t
    JOIN Employee e ON t.IssuedByEmployeeID = e.EmployeeID
    JOIN Itinerary i ON t.ItineraryID = i.ItineraryID
    JOIN ItinerarySegment iseg ON i.ItineraryID = iseg.ItineraryID
    JOIN Flight f ON iseg.FlightID = f.FlightID
    JOIN SegmentBase sb ON iseg.ItineraryID = sb.ItineraryID AND iseg.FlightID = sb.FlightID
    LEFT JOIN BaggageFees bf ON i.ItineraryID = bf.ItineraryID
    LEFT JOIN MealFees mf ON i.ItineraryID = mf.ItineraryID;
GO

-- SELECT FROM EmployeeFlightRevenueView.
SELECT *,
       SUM(SegmentRevenue) OVER (PARTITION BY EmployeeID) AS TotalEmployeeRevenue
FROM EmployeeFlightRevenueView
ORDER BY TotalEmployeeRevenue DESC, EmployeeID;

-- SELECT FOR SPECIFIC ID
SELECT *
FROM EmployeeFlightRevenueView
WHERE EmployeeID=5;

-- QUESTION 6: Update Seat Allotment to Reserved Upon Ticket Issue

-- Display passenger and seat status BEFORE triggering the ticket issuance
SELECT 
    p.PassengerID, 
    p.FirstName, 
    p.LastName, 
    i.PNR, 
    i.Status AS ItineraryStatus, 
    s.SeatNumber, 
    s.SeatClass, 
    s.SeatStatus
FROM 
    Passenger p
JOIN 
    Itinerary i ON p.PassengerID = i.PassengerID
JOIN 
    ItinerarySegment s ON i.ItineraryID = s.ItineraryID
WHERE 
    i.PNR = 'GHI789';
    
-- CREATE A TRIGGER TO UPDATE SeatStatus to Reserved.
GO
CREATE TRIGGER after_ticket_issue
ON Ticket
AFTER INSERT
AS
BEGIN
    UPDATE ItinerarySegment
    SET SeatStatus = 'Reserved'
    FROM ItinerarySegment iseg
    INNER JOIN INSERTED i ON iseg.ItineraryID = i.ItineraryID
    WHERE iseg.SeatStatus = 'Available';
END;
GO

EXEC sp_IssueTicket 'GHI789', 1;

-- Display passenger and seat status AFTER triggering the ticket issuance
SELECT 
    p.PassengerID, 
    p.FirstName, 
    p.LastName, 
    i.PNR, 
    i.Status AS ItineraryStatus, 
    s.SeatNumber, 
    s.SeatClass, 
    s.SeatStatus
FROM 
    Passenger p
JOIN 
    Itinerary i ON p.PassengerID = i.PassengerID
JOIN 
    ItinerarySegment s ON i.ItineraryID = s.ItineraryID
WHERE 
    i.PNR = 'GHI789';
    
-- QUESTION 7): Checked-In Baggage Count and Weight by Flight and Date
GO
CREATE VIEW FlightBaggageCountView AS
SELECT 
    f.FlightID,
    f.FlightNumber,
    f.Origin,
    f.Destination,
    f.DepartureTime,
    COUNT(DISTINCT b.BaggageID) AS TotalCheckedInBaggage,
    SUM(b.BaggageWeight) AS TotalBaggageWeight
FROM 
    Flight f
    JOIN ItinerarySegment iseg ON f.FlightID = iseg.FlightID
    JOIN Itinerary i ON iseg.ItineraryID = i.ItineraryID
    JOIN Baggage b ON i.ItineraryID = b.ItineraryID
WHERE 
    b.BaggageStatus = 'CheckedIn'
GROUP BY 
    f.FlightID, f.FlightNumber, f.Origin, f.Destination, f.DepartureTime;
GO    
-- Display the Results
SELECT * FROM FlightBaggageCountView
ORDER BY TotalBaggageWeight DESC;




