from datetime import datetime

def get_ctime_cdate(date=None,time=None,splitter=False):
    if not splitter:
        ctd = datetime.now()
        cdate,ctime = str(ctd.date()),str(ctd.strftime('%I:%M:%S'))
    else:
        cdate,ctime = str(date),str(time)
    return {
        'date':cdate,
        'time':ctime,
        'sep_date':{
            'day':cdate.split('-')[-1],
            'mon':cdate.split('-')[1],
            'year':cdate.split('-')[0]
        },
        'sep_time':{
            'H':ctime.split(':')[0],
            'M':ctime.split(':')[1],
            'S':ctime.split(':')[-1]
        }
    }

def data_time_validator(date, time):
    get_ctd = get_ctime_cdate(splitter=False)
    get_o_ctd = get_ctime_cdate(date, time, splitter=True)

    current = datetime(
        int(get_ctd['sep_date']['year']),
        int(get_ctd['sep_date']['mon']),
        int(get_ctd['sep_date']['day']),
        int(get_ctd['sep_time']['H']),
        int(get_ctd['sep_time']['M']),
        int(get_ctd['sep_time']['S'])
    )

    expiry = datetime(
        int(get_o_ctd['sep_date']['year']),
        int(get_o_ctd['sep_date']['mon']),
        int(get_o_ctd['sep_date']['day']),
        int(get_o_ctd['sep_time']['H']),
        int(get_o_ctd['sep_time']['M']),
        int(get_o_ctd['sep_time']['S'])
    )

    return expiry > current

def normalize_contact(value):
    value = (value or "").strip()
    if not value:
        return ""

    if value.lower().startswith("mailto:"):
        value = value.split(":", 1)[1].strip()

    return value


def normalize_expires(value):
    value = (value or "").strip()
    if not value:
        return {"raw": "", "valid": False}

    try:
        clean_value = value.replace(" ", "").replace("Z", "")
        if "T" in clean_value:
            date_part = clean_value.split("T")[0]
            time_part = clean_value.split("T")[1].split(".")[0]
            valid = data_time_validator(date_part, time_part)
            return {
                "raw": value,
                "clean": f"{date_part} {time_part}",
                "valid": valid
            }
    except Exception:
        pass

    return {
        "raw": value,
        "clean": value,
        "valid": False
    }


def normalize_policy(value):
    return (value or "").strip()


def normalize_encryption(value):
    return (value or "").strip()


def normalize_language(value):
    value = (value or "").strip()
    if not value:
        return ""

    lang_map = {
        "en": "English",
        "fr": "French",
        "es": "Spanish",
        "de": "German",
        "pt": "Portuguese"
    }

    return lang_map.get(value.lower(), value)
