# CertWatch — מדריך התקנה והפעלה

## מה הכלי עושה
- סורק טווח IP ברשת (ping מקבילי מהיר)
- מתחבר לכל שרת פעיל דרך WinRM
- שולף תעודות מ-**LocalMachine\My (Personal)**
- מסמן תעודות לפי דחיפות: קריטי / אזהרה / תשומת לב / תקין
- מאפשר סינון, מיון, וייצוא CSV

---

## דרישות מקדימות

### Python
הורד מ: https://www.python.org/downloads/
(בחר Python 3.10 ומעלה, סמן ✅ "Add to PATH")

### ספריות
פתח CMD כ-Administrator והרץ:
```
pip install pywinrm
```

---

## הפעלה
```
python cert_scanner.py
```
או לחץ פעמיים על הקובץ (אם Python מוגדר כ-default)

---

## הגדרות WinRM בשרתים (חובה!)

על כל שרת שרוצים לסרוק, הרץ PowerShell כ-Administrator:

```powershell
# הפעל WinRM
Enable-PSRemoting -Force

# אפשר חיבור מה-management server שלך (החלף IP)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.1.100" -Force

# בדוק סטטוס
winrm quickconfig
```

---

## שימוש בממשק

### טווח IP — פורמטים נתמכים
| פורמט | דוגמה |
|--------|--------|
| Range של אוקטט אחרון | `192.168.1.1-254` |
| CIDR | `192.168.1.0/24` |
| רשימה | `192.168.1.10,192.168.1.20` |
| IP בודד | `192.168.1.50` |

### אישורים
- **משתמש נוכחי** — אם אתה Domain Admin מחובר, זה עובד אוטומטי (Kerberos)
- **Username/Password** — אם תצטרך לציין משתמש ידנית (NTLM)

### ספי התראות
| צבע | ברירת מחדל | משמעות |
|------|------------|---------|
| 🔴 קריטי | 30 יום | פג תוקף תוך חודש |
| 🟡 אזהרה | 60 יום | פג תוקף תוך חודשיים |
| 🔵 תשומת לב | 90 יום | פג תוקף תוך 3 חודשים |

---

## פתרון בעיות נפוצות

**שגיאת WinRM / Access Denied**
- ודא שה-WinRM פעיל בשרת היעד
- ודא שאתה Domain Admin
- בדוק FW — פורט **5985** (HTTP) או **5986** (HTTPS) פתוח

**ping עובד אבל תעודות לא נשלפות**
- ייתכן ש-WinRM לא מופעל על השרת
- הרץ: `Test-WSMan -ComputerName <IP>` מ-PowerShell

**`pywinrm` לא מותקן**
```
pip install pywinrm
```

---

## ייצוא CSV
לחץ **💾 ייצוא CSV** — ייפתח חלון שמירה.
הקובץ כולל: IP, Hostname, Subject, Issuer, תאריך פקיעה, ימים נותרים, סטטוס.
