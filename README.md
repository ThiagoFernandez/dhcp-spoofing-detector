# DHCP Spoofing Lab — Rogue DHCP + Detector

Laboratorio de **ataque y defensa sobre DHCP** (Capa 2). Dos piezas que se prueban entre sí:
un **servidor DHCP rogue** (ataque) y un **detector host-side** que lo caza comparando el
origen de los Offers contra una whitelist de confianza (idea de **DHCP Snooping** llevada al host).

Parte del roadmap propio de ciberseguridad con Python (Fase 3 — ataques de Capa 2).

> ⚠️ **Uso educativo / laboratorio aislado.** Corré esto **solo** en una red de pruebas
> aislada y bajo tu control (acá: red `redzone` `10.10.10.0/24`). Levantar un DHCP rogue
> en una red ajena es ilegal y rompe la red. No lo uses fuera de un entorno autorizado.

---

## Componentes

| Archivo | Rol | Qué hace |
|---------|-----|----------|
| `dhcp_spoofing.py` | **Ataque** | Servidor DHCP rogue: responde Discover/Request con Offer/Ack apuntando `router` (gateway) y `name_server` (DNS) a sí mismo → **MITM**. |
| `dhcp_detector.py` | **Defensa** | Escucha DHCP, filtra Offers/Ack (message-type 2/5) y **alerta** si el origen no está en `trust_file.json`. Loguea en JSONL. |
| `trust_file.json` | Config | Whitelist del/los server(es) DHCP legítimo(s): `{"<ip>": "<mac>"}`. |
| `send_discover.py` *(opcional)* | Test | Dispara un DHCP Discover a mano con scapy para provocar Offers sin cliente real. |

---

## Requisitos

- Linux (probado en Kali / Arch)
- Python 3
- [`scapy`](https://scapy.net/) → `pip install scapy`
- Privilegios de root (captura y envío crudo de paquetes) → `sudo`

---

## Uso

### 1. Servidor rogue (ataque)

```bash
sudo python3 dhcp_spoofing.py -r 10.10.10.0/24 -i eth0
```

| Flag | Descripción |
|------|-------------|
| `-r, --red` | **(requerido)** Red a servir, ej. `10.10.10.0/24` |
| `-i, --iface` | Interfaz de red (ej. `eth0`) |
| `-d, --duration` | Duración en segundos (`0` = infinito) |
| `-l, --lease` | Tiempo de lease ofrecido |

El rogue queda escuchando y **responde cuando alguien pide** (Discover/Request). Gana por
velocidad: si contesta antes que el server legítimo, la víctima toma su gateway/DNS.

### 2. Detector (defensa)

Primero definí los servidores DHCP legítimos en `trust_file.json`:

```json
{
  "10.10.10.1": "52:54:00:ae:c4:9f"
}
```

Después corré el detector (necesita el `trust_file.json` en el directorio actual):

```bash
sudo python3 dhcp_detector.py -i eth0
```

| Flag | Descripción |
|------|-------------|
| `-i, --iface` | **(requerido)** Interfaz a escuchar |
| `-c, --count` | Límite de paquetes a capturar (`0` = infinito) |

Ante un Offer/Ack desde un origen **no confiable**, imprime la alerta y la escribe en
`dhcp_spoof_alert.jsonl`:

```
[dhcp spoofing] Datos del rogue: 10.10.10.183 --- 52:54:00:b1:ee:2c
```

```json
{"timestamp": "...", "level": "WARNING", "msg": "[dhcp spoofing] ...",
 "tipo": "dhcp spoofing", "gateway_dado": "10.10.10.183",
 "dns_dado": "10.10.10.183", "server_id_dado": "10.10.10.183"}
```

### 3. Generar tráfico de prueba (opcional)

Si no tenés un cliente que pida IP, un Discover es broadcast y lo podés disparar a mano:

```bash
sudo python3 send_discover.py    # ver iface dentro del script
```

---

## Cómo funciona la detección

1. Filtra paquetes que tengan capa `DHCP`.
2. Lee `message-type`; sigue **solo** con **2 (Offer)** y **5 (Ack)** — los mensajes que
   manda un *servidor*. Un Discover/Request (cliente) se descarta.
3. Extrae `ip` y `mac` de origen + `server_id`, `router` (gateway) y `name_server` (DNS).
4. **Decisión:** compara el origen contra la whitelist:
   - IP **no está** en `trust_file.json` → `data.get(ip)` es `None` → **server desconocido**.
   - IP **sí está** pero la **MAC no coincide** → **mac mismatch** (alguien clonó la IP del server).
   - En cualquiera de los dos casos → **alerta** (con cooldown por `(ip, mac)` para no spamear).

### ¿Dónde está el MITM?

No en la IP que reparte, sino en las **opciones** del Offer: `router` (gateway) y
`name_server` (DNS) apuntando al atacante. Así todo el tráfico de la víctima sale **por el
atacante** antes de ir a Internet. Esos campos quedan en el log como prueba.

---

## Limitaciones (punto ciego)

Este detector es **host-side**: solo ve el tráfico que llega a su interfaz. En una red
**conmutada**, el switch entrega el Offer **solo al puerto del cliente que lo pidió**
(unicast), así que un detector parado en otro host **no lo ve** salvo que sea el destino o
que el frame sea broadcast.

La mitigación real vive en el **switch**: **DHCP Snooping** — marca puertos *trusted* /
*untrusted* y descarta mensajes de servidor (Offer/Ack) que lleguen por un puerto untrusted.
Este proyecto **imita** esa idea desde el host con fines de aprendizaje.

---

## Roadmap

- [x] Rogue DHCP operativo (Offer/Ack con MITM en gateway/DNS)
- [x] Detector v1: whitelist IP/MAC + alerta + log JSONL
- [ ] **Detector v2:** cazar al rogue que *clona* identidad (IP+MAC+`server_id` del legítimo)
      contando **dos Offers con el mismo `xid` desde distintos `server_id`**
- [ ] Robustez: filtrar marcadores `end`/`pad` de las options; capturar el verdadero-negativo
- [ ] Ataque de **DHCP starvation** (agotar el pool con MACs falsas)

---

## Disclaimer

Material educativo de seguridad ofensiva/defensiva. El autor no se responsabiliza por el
mal uso. Usar únicamente en entornos propios y aislados o con autorización explícita.
