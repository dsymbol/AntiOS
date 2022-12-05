import os
import subprocess
import sys
import argparse
import winreg
import system_fingerprint
import hardware_fingerprint
import telemetry_fingerprint
import random_utils
import registry_helper


from registry_helper import RegistryKeyType, Wow64RegistryEntry
from system_utils import is_x64os, platform_version


def generate_telemetry_fingerprint():
    """
    IDs related to Windows 10 Telemetry
    All the telemetry is getting around the DeviceID registry value
    It can be found in the following kays:
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests
    """
    windows_ver = platform_version()
    if not windows_ver.startswith("Windows-10"):
        print(">> Telemetry ID replace available for Windows 10 only")
        return

    current_device_id = registry_helper.read_value(
        key_hive="HKEY_LOCAL_MACHINE",
        key_path="SOFTWARE\\Microsoft\\SQMClient",
        value_name="MachineId")
    if current_device_id[1] == winreg.REG_SZ:
        print(">> Current Windows 10 Telemetry DeviceID is {0}".format(current_device_id[0]))
    else:
        print(">> Unexpected type of HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient Value:MachineId Type:%d" %
                       current_device_id[1])
        return

    telemetry_fp = telemetry_fingerprint.TelemetryFingerprint()
    device_id = telemetry_fp.random_device_id_guid()
    device_id_brackets = "{%s}" % telemetry_fp.random_device_id_guid()
    print(">> New Windows 10 Telemetry DeviceID is {0}".format(device_id_brackets))

    registry_helper.write_value(key_hive="HKEY_LOCAL_MACHINE",
                                key_path="SOFTWARE\\Microsoft\\SQMClient",
                                value_name="MachineId",
                                value_type=winreg.REG_SZ,
                                key_value=device_id_brackets)

    # Replace queries
    query_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\SettingsRequests"
    setting_requests = registry_helper.enumerate_key_subkeys(key_hive="HKEY_LOCAL_MACHINE",
                                                             key_path=query_path)
    print(">> SettingsRequest subkeys: {0}".format(setting_requests))

    for request in setting_requests:
        query_params = registry_helper.read_value(key_hive="HKEY_LOCAL_MACHINE",
                                                  key_path="%s\\%s" % (query_path, request),
                                                  value_name="ETagQueryParameters")
        if query_params[1] != winreg.REG_SZ:
            print(">> Unexpected type of %s\\%s Value:MachineId Type:%d" % (query_path, request, query_params[1]))
            return

        query_string = query_params[0]
        new_query_string = query_string.replace(current_device_id[0], device_id)
        registry_helper.write_value(key_hive="HKEY_LOCAL_MACHINE",
                                    key_path="%s\\%s" % (query_path, request),
                                    value_name="ETagQueryParameters",
                                    value_type=winreg.REG_SZ,
                                    key_value=new_query_string)

    print(">> DeviceID has been replaced from %s to %s" % (current_device_id, device_id))


def generate_network_fingerprint():
    """
    Generate network-related identifiers:
    Hostname (from pre-defined list)
    Username (from pre-defined list)
    MAC address (powershell script)
    """
    random_host = random_utils.random_hostname()
    random_user = random_utils.random_username()
    random_mac = random_utils.random_mac_address()
    print(">> Random hostname value is {0}".format(random_host))
    print(">> Random username value is {0}".format(random_user))
    print(">> Random MAC address value is {0}".format(random_mac))

    hive = "HKEY_LOCAL_MACHINE"
    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="NV Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                                value_name="Hostname",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                                value_name="ComputerName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_host)

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                value_name="RegisteredOwner",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=random_user,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)


def generate_windows_fingerprint():
    """
    Generate common Windows identifiers, responsible for fingerprinting:
    BuildGUID
    BuildLab
    BuildLabEx
    CurrentBuild
    CurrentBuildNumber
    CurrentVersion
    DigitalProductId
    DigitalProductId4
    EditionID
    InstallDate
    ProductId
    ProductName
    IE SvcKBNumber
    IE ProductId
    IE DigitalProductId
    IE DigitalProductId4
    IE Installed Date
    """
    system_fp = system_fingerprint.WinFingerprint()

    # Windows fingerprint
    hive = "HKEY_LOCAL_MACHINE"
    version_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildGUID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_guid(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLab",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="BuildLabEx",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_build_lab_ex(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuild",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentBuildNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_build(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="CurrentVersion",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_current_version(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="EditionID",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_edition_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="InstallDate",
                                value_type=RegistryKeyType.REG_DWORD,
                                key_value=system_fp.random_install_date())

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path=version_path,
                                value_name="ProductName",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_name(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer",
                                value_name="svcKBNumber",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_ie_service_update(),
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="ProductId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=system_fp.random_product_id())

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id()))

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Registration",
                                value_name="DigitalProductId4",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(system_fp.random_digital_product_id4()))

    ie_install_date = system_fp.random_ie_install_date()

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Internet Explorer\\Migration",
                                value_name="IE Installed Date",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=ie_install_date,
                                access_type=Wow64RegistryEntry.KEY_WOW32_64)

    print(">> Random build GUID {0}".format(system_fp.random_build_guid()))
    print(">> Random BuildLab {0}".format(system_fp.random_build_lab()))
    print(">> Random BuildLabEx {0}".format(system_fp.random_build_lab_ex()))
    print(">> Random Current Build {0}".format(system_fp.random_current_build()))
    print(">> Random Current Build number {0}".format(system_fp.random_current_build()))
    print(">> Random Current Version {0}".format(system_fp.random_current_version()))
    print(">> Random Edition ID {0}".format(system_fp.random_edition_id()))
    print(">> Random Install Date {0}".format(system_fp.random_install_date()))
    print(">> Random product ID {0}".format(system_fp.random_product_id()))
    print(">> Random Product name {0}".format(system_fp.random_product_name()))


def generate_hardware_fingerprint():
    """
    Generate hardware-related identifiers:
    HwProfileGuid
    MachineGuid
    Volume ID
    SusClientId
    SusClientIDValidation
    """

    hardware_fp = hardware_fingerprint.HardwareFingerprint()

    hive = "HKEY_LOCAL_MACHINE"
    # Hardware profile GUID

    registry_helper.write_value(key_hive=hive,
                                key_path="SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                                value_name="HwProfileGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_hw_profile_guid())

    # Machine GUID
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Cryptography",
                                value_name="MachineGuid",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_machine_guid())

    # Windows Update GUID
    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientId",
                                value_type=RegistryKeyType.REG_SZ,
                                key_value=hardware_fp.random_win_update_guid())

    registry_helper.write_value(key_hive=hive,
                                key_path="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
                                value_name="SusClientIDValidation",
                                value_type=RegistryKeyType.REG_BINARY,
                                key_value=random_utils.bytes_list_to_array(hardware_fp.random_client_id_validation()))

    executable = os.path.join(os.path.dirname(__file__), "bin", "VolumeID{0}.exe".format("64" if is_x64os() else ""))
    volume_id = random_utils.random_volume_id()
    command = [executable, '-nobanner', 'C:', volume_id]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    volume_id_message = result.stderr if result.returncode != 0 else result.stdout
    print(f">> {volume_id_message}", end="")
    print(">> Random Hardware profile GUID {0}".format(hardware_fp.random_hw_profile_guid()))
    print(">> Random Hardware CKCL GUID {0}".format(hardware_fp.random_performance_guid()))
    print(">> Random Machine GUID {0}".format(hardware_fp.random_machine_guid()))
    print(">> Random Windows Update GUID {0}".format(hardware_fp.random_win_update_guid()))
    print(">> Random Windows Update Validation ID {0}".format(hardware_fp.random_win_update_guid()))


def main():
    """
    Generate and change/spoof Windows identification to protect user from local installed software
    :return: Exec return code
    """

    parser = argparse.ArgumentParser(description='Command-line parameters')

    parser.add_argument('--telemetry',
                        help='Generate Windows 10 Telemetry IDs',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--network',
                        help='Generate network-related fingerprint',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--system',
                        help='Generate fingerprint based on system version and identifiers',
                        action='store_true',
                        required=False,
                        default=False)

    parser.add_argument('--hardware',
                        help='Generate fingerprint based on hardware identifiers',
                        action='store_true',
                        required=False,
                        default=False)

    args = parser.parse_args()

    # Selected nothing means select all
    if args.telemetry is False and args.network is False and args.system is False and args.hardware is False:
        args.network = True
        args.system = True
        args.hardware = True

    if args.telemetry:
        generate_telemetry_fingerprint()
    if args.network:
        generate_network_fingerprint()
    if args.system:
        generate_windows_fingerprint()
    if args.hardware:
        generate_hardware_fingerprint()

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
