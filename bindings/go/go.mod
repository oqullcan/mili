// mili's Go binding. It has no dependencies beyond the C library it links, on
// purpose: a security library whose binding pulls in a module graph has a supply
// chain a user did not choose.
module mili

go 1.24.0
