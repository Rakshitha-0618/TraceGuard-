# RBAC test plan

1. Log in as reporter and submit a uniquely named complaint.
2. Log in as admin in another browser profile; complaint should appear as Not assigned.
3. Log in as investigator before assignment; complaint should NOT appear.
4. Admin selects investigator and clicks Assign / reassign.
5. Refresh investigator view; complaint should now appear.
6. Investigator updates status and adds internal note.
7. Reporter can see own complaint but cannot see internal notes or other reporters' cases.
8. Confirm reporter assignment attempt returns HTTP 403; investigator access to /api/users returns HTTP 403; investigator update to unassigned case returns HTTP 403.
