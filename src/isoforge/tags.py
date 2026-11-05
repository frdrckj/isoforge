TAG_NAMES: dict[str, str] = {
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F10": "Issuer Application Data",
    "95": "Terminal Verification Results",
    "9A": "Transaction Date",
    "9C": "Transaction Type",
    "9F02": "Amount Authorised",
    "5F2A": "Transaction Currency Code",
    "82": "Application Interchange Profile",
    "84": "Dedicated File Name",
    "9F37": "Unpredictable Number",
    "9F36": "Application Transaction Counter",
    "9F1A": "Terminal Country Code",
}


def lookup(tag: str) -> str:
    return TAG_NAMES.get(tag.upper(), "unknown")
