from dsp3.models.manager import Manager



dsm = Manager(username="username", password="password", host="127.0.0.1", port="4119")


# Example 1: Retrieve DSM version.
version = dsm.manager_info_version()

# Example 2: Retrieve the status summary of the system.
status_summary = dsm.manager_info_status_summary()

#Example 3: Retrieve the status summary of each protection feature.
feature_summary = dsm.manager_info_feature_summary(1)

# Example 4: Retrieves detailed component info in current system
component_info = dsm.manager_info_components()
print(component_info)

dsm.end_session()
