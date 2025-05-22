# ✈️ Airport Ticket Booking System (SQL Server | 3NF Normalized)

This project is a comprehensive **Airport Ticket Booking System** developed using **Microsoft SQL Server**, designed with strict adherence to **Third Normal Form (3NF)** principles. It efficiently handles flight reservations, secure logins, passenger updates, and employee operations with strong data validation and security measures in place.

---

## 📚 What This Project Does

The system begins with designing and creating a fully normalized database schema with well-defined relationships, constraints, and validations. All objects were created with **referential integrity**, **data validation checks**, and logical rules — such as validating email formats, checking date of birth constraints, enforcing valid class types, and ensuring proper associations between passengers, flights, and employees.

A detailed **Entity Relationship Diagram (ERD)** was constructed to visualize relationships and ensure normalization rules were followed, removing redundancy and enforcing dependency on primary keys only.

<img width="902" alt="Screenshot 2025-05-22 at 19 37 24" src="https://github.com/user-attachments/assets/f3f1e40f-9fc5-449c-936b-bd2601c7a726" />

Authentication is handled via a **secure login procedure** for employees. Passwords are **hashed and salted** using `SHA2_256` via SQL Server's `HASHBYTES()` function. Although a static salt is currently used, it ensures credentials are stored securely and prevents plaintext vulnerabilities.

To support the boarding process, a stored procedure generates **unique boarding numbers** by combining internal identifiers with a deterministic hash component, ensuring uniqueness even during concurrent operations. These are stored in a separate table for streamlined boarding workflows.

Security is a key focus of this system:
- Passwords are stored as secure hashes.
- `HASHBYTES` with `SHA2_256` is used for encryption.
- Salting is used to enhance hash uniqueness.

To test and demonstrate functionality, several real-world **use case queries** were implemented:
 
  **Search** for passengers by last name, with the most recent bookings listed first.
<img width="860" alt="Screenshot 2025-05-22 at 19 39 10" src="https://github.com/user-attachments/assets/c5546822-fd72-40bc-9080-d7e2a599f1eb" />

  Retrieve **meal preferences** for business class passengers who booked today.
 <img width="984" alt="Screenshot 2025-05-22 at 19 39 31" src="https://github.com/user-attachments/assets/8481db2b-5d84-406e-be3d-c546be221a63" />
View **revenue and boarding activity** grouped by employee.
 <img width="948" alt="Screenshot 2025-05-22 at 19 40 09" src="https://github.com/user-attachments/assets/0130938a-0bac-4709-8bb4-dae176f31b4f" />
<img width="973" alt="Screenshot 2025-05-22 at 19 40 33" src="https://github.com/user-attachments/assets/39a46a3a-0d06-45f1-a7ca-a7bcf0ea06aa" />

 Use a **trigger** to automatically update seat availability when a booking is made.
<img width="880" alt="Screenshot 2025-05-22 at 19 41 09" src="https://github.com/user-attachments/assets/950b6055-a771-4236-a229-1f8149476ce8" />

 Generate **baggage count reports** by flight and booking date.
<img width="914" alt="Screenshot 2025-05-22 at 19 41 26" src="https://github.com/user-attachments/assets/98e2fb3b-7d59-4d15-b923-84b44f98fffb" />

These queries validate that the system operates as expected and support operational airport workflows in a scalable and secure manner.

---

## 🧑‍💻 How to Run This Project on Your System

### ✅ Prerequisites

- Microsoft SQL Server 2017 or newer
- SQL Server Management Studio (SSMS)
- Basic knowledge of T-SQL

### 🧾 Setup Instructions

1. **Download the SQL Script**
   - Clone the repo.

2. **Open in SQL Server Management Studio**
   - Launch SSMS.
   - Open the SQL file.

3. **Create a New Database**
   ```sql
   CREATE DATABASE AirportReservationsDB;
   USE AirportReservationsDB;
