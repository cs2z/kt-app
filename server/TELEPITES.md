# KT köztes szerver telepítése (egyszeri belépés)

Ez a leírás Zoltánnak szól. A VPS (Tárhely.Eu, Ubuntu 24.04, `185.208.226.186`) már megvan. A DNS a `ktbp.hu` alatt még nincs kész; elsőre a `https://185-208-226-186.sslip.io` címet használjuk, ez a nyilvános IP-re mutat.

A telepítő **egyetlen parancs**. Utána a szerver 10 percenként magától frissül a GitHubról.

## Amit előkészítesz

- A VPS **root jelszava** a Tárhely.Eu rendelési / üdvözlő e-mailjében van.
- A **BKK API-kulcs**, amit az app Beállítás fülén is használsz.
- Kb. 5–10 perc, amíg a csomagok és a HTTPS-tanúsítvány elkészülnek.

A jelszót, a BKK-kulcsot és a kliens tokent **ne másold chatbe**, ne küldd el üzenetben, ne tedd GitHubra.

## 1. Belépés a szerverre

### Windows (Windows Terminal vagy PowerShell)

1. Nyisd meg a Windows Terminált vagy a PowerShellt.
2. Írd be:

   ```text
   ssh root@185.208.226.186
   ```

3. Első alkalommal a program megkérdezi, hogy elfogadod-e a szerver ujjlenyomatát. Ellenőrizheted a Tárhely.Eu levelében, ha szerepel, majd írd: `yes`.
4. Add meg a root jelszót (begépeléskor nem látszik). Beillesztés: jobb klikk vagy `Shift+Insert`, majd Enter.

Ha az `ssh` parancs nem ismert, a Windows beállításainál kapcsold be az „OpenSSH-kliens” opcionális szolgáltatást, vagy használj Windows Terminált / PuTTY-t ugyanerre a címre, root felhasználóval.

### Ha az SSH nem megy (telefon vagy böngésző)

A Tárhely.Eu VPS-kezelőfelületén van böngészős konzol (noVNC / SPICE / Xterm.js). A pontos menüpont a szolgáltatói felületen vagy a rendelési e-mailben szerepel; itt nem találgatjuk a gombok nevét. Lépj be rootként, és ugyanazt a parancsot illeszd be.

Ha a felületen van **VPS Tűzfal** és be van kapcsolva, engedélyezd a **22**, **80** és **443** portokat, különben a belépés vagy a HTTPS-tanúsítvány elakadhat.

## 2. A telepítő parancs

A root parancssorba illeszd be ezt a sort, majd Enter:

```bash
curl -fsSL https://cs2z.github.io/kt-app/server/install.sh | bash
```

Ha ez 404-es hibát ad (a GitHub Pages néha pár percet késik), használd ezt:

```bash
curl -fsSL https://raw.githubusercontent.com/cs2z/kt-app/main/server/install.sh | bash
```

A script csomagokat telepít, létrehozza a `kt` felhasználót, beállítja a Caddy HTTPS-proxyt és a tűzfalat (22, 80, 443).

Amikor kéri a **BKK API-kulcsot**, gépeld vagy illeszd be. A begépelés nem látszik. Zárd Enterrel. A kulcs a szerveren marad (`/etc/kt-server/env`), a képernyőre nem íródik ki.

A script **egyszer kiírja a kliens tokent** a te terminálodra. Ezt jegyezd fel magadnak (jelszókezelő, jegyzet a gépeden). **Ne küldd el chatbe.** Később megnézheted:

```bash
sudo cat /etc/kt-server/client-token
```

A végén egy rövid magyar összefoglaló jelenik meg, benne a `https://…` címmel és a `/health` válaszával.

## 3. Mit küldj vissza

Csak ezt a kettőt:

- a kiírt HTTPS URL-t (elsőre várhatóan `https://185-208-226-186.sslip.io`);
- a `/health` eredményét (például `OK` és egy rövid JSON, vagy a hibaüzenet).

**Ne küldd:** root jelszó, BKK-kulcs, kliens token, a `/etc/kt-server/env` tartalma, képernyőkép ezekről.

## 4. A ktbp.hu később

Amikor a `ktbp.hu` névjegyeire beállítottad a névszervereket, és a domain a `185.208.226.186` címre mutat, a szerveren (rootként) futtasd:

```bash
sudo kt-set-domain ktbp.hu
```

Ez átírja a Caddy beállítását, kér egy új HTTPS-tanúsítványt a `ktbp.hu`-ra, és a régi sslip.io cím is megmarad, amíg át nem állunk. Addig az appban is a sslip.io URL-t használjuk.

## Hasznos parancsok (ha valami elakad)

```bash
systemctl status kt-server --no-pager
journalctl -u kt-server -n 80 --no-pager
curl -s http://127.0.0.1:8787/health
curl -s https://185-208-226-186.sslip.io/health
```

A telepítő újra futtatható: a meglévő kulcsot és tokent nem írja felül.
