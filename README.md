# dhcp_spoofing_detector.py — Detector de Rogue DHCP (DHCP Snooping host-side)

Detector defensivo que escucha el tráfico DHCP de una LAN y **alerta ante servidores
DHCP no autorizados**. Es DHCP Snooping del lado del host: separa los orígenes
confiables (whitelist) de los que no, y además — en su versión **v2** — detecta al
atacante **clone** que roba la identidad del server legítimo, mirando si el
**gateway/DNS** que reparte coincide con el real.

> Contraparte del rogue del repo `dhcp-spoofing`. El valor pedagógico del proyecto
> vive acá: el ataque es el banco de pruebas, el detector es lo que importa.

---

## Qué detecta

Escucha `udp and (port 67 or port 68)` y analiza los **Offer (2)** y **Ack (5)**
(los mensajes que manda un *servidor*). Para cada uno hace **dos niveles** de chequeo
contra la whitelist (`trust_file.json`):

1. **Identidad (v1):** ¿el `IP.src` del Offer está en la whitelist y su `white_mac`
   coincide con el `Ether.src`? Si no → **alerta** (servidor desconocido o MAC
   suplantada). Caza al rogue ingenuo.

2. **Comportamiento / MITM (v2):** si la identidad **sí** matchea (un clone que robó
   IP+MAC+`server_id` del server real pasaría este primer filtro), compara el
   `router` (`white_gateway`) y el `name_server` (`white_dns`) que advertisa el Offer
   contra los valores confiables. Si **difieren** → **alerta**. Esta es la señal que
   un clone no puede falsear sin dejar de hacer MITM: para envenenar tiene que
   repartir **su** gateway/DNS, y ahí se delata.

> **Por qué hizo falta v2:** v1 confiaba solo por identidad (IP/MAC), y la identidad
> **se clona**. El clone del repo `dhcp-spoofing` copia IP+MAC+`server_id` del server
> legítimo → v1 lo deja pasar (agujero confirmado en el lab). v2 agrega una señal de
> **comportamiento** (gateway/DNS) que el disfraz de identidad no cubre.

---

## Dependencias

- Python 3
- [Scapy](https://scapy.net/) (`pip install scapy`)
- Privilegios de root (sniffing en modo promiscuo)

## Uso

```bash
sudo python3 dhcp_spoofing_detector.py -i <IFACE> [-c N]
```

| Flag | Descripción | Default |
|------|-------------|---------|
| `-i`, `--iface` | **(requerido)** Interfaz a escuchar (ej. `eth0`). | — |
| `-c`, `--count` | Límite de paquetes a capturar (`0` = infinito). | `0` |

```bash
sudo python3 dhcp_spoofing_detector.py -i eth0
```

---

## Whitelist: `trust_file.json`

Mapea cada servidor DHCP confiable a su identidad y a los valores que **debería**
repartir. **Verificá estos datos con los de tu red antes de correrlo** (la identidad
del server legítimo cambia por entorno).

```json
{
    "10.10.10.1": {
        "white_mac": "52:54:00:ae:c4:9f",
        "white_gateway": null,
        "white_dns": "10.10.10.1"
    }
}
```

- `white_mac` — MAC esperada del server (se compara en minúscula).
- `white_gateway` — opción `router` esperada (`null` si el server legítimo no la
  advertisa; entonces cualquier `router` ≠ `null` es sospechoso).
- `white_dns` — opción `name_server` esperada.

---

## Salida

### Consola
```
[dhcp spoofing] Datos del rogue: 10.10.10.1 --- 52:54:00:ae:c4:9f ---
```

### Log estructurado — `dhcp_spoof_alert.jsonl`

Una línea JSON por alerta (nivel `WARNING`), con la evidencia del MITM:

```json
{"timestamp": "2026-11-03T22:51:29.338741+00:00", "level": "WARNING",
 "msg": "[dhcp spoofing] Datos del rogue: 10.10.10.1 --- 52:54:00:ae:c4:9f --- ",
 "tipo": "dhcp spoofing", "gateway_dado": "10.10.10.183",
 "dns_dado": "10.10.10.183", "server_id_dado": "10.10.10.1"}
```

En este ejemplo (clone cazado por v2): `server_id_dado` = `10.10.10.1` (identidad
**clonada**, en la whitelist) pero `gateway_dado`/`dns_dado` = `10.10.10.183` (el
atacante). Identidad confiable + gateway/DNS envenenado = **clone detectado**.

### Anti-spam
Cooldown de **5 s** por `(ip, mac)` (`ALERT_COOLDOWN`): no repite la misma alerta en
ráfaga.

---

## Límite conocido (y por qué existe DHCP Snooping en el switch)

Un detector de host confía por **identidad** (falsificable desde software) y, en una
red conmutada, el switch manda el Offer solo al puerto del cliente (unicast): el
detector no lo ve salvo que el tráfico sea broadcast. La mitigación robusta es
**DHCP Snooping en el switch**, que confía por **puerto físico** — eso no se falsea
desde software. Este detector es la versión host-side, pedagógica, de ese mismo
principio.

---

## Relacionado

- **Ataque que caza:** repo `dhcp-spoofing` (`dhcp_spoofing.py`, modo `--clone`).
- **Patrón de logging** reusado del detector ARP (ARP spoofing ↔ DAI) y del Sniffer.
