-- TC1: create and drop user
create user test_user_management identified by test_user_management; 
drop user test_user_management; 

-- TC2: Create, alter, insert update
BEGIN
create table Customers (Name varchar2(100));
ALTER TABLE Customers
ADD Email varchar(255);
insert into Customers values ('David', 'david@example.com');
update Customers set Name = 'David Beckham' where  Email = 'david@example.com';
select * from Customers;
delete Customers;
drop table Customers; 
END

