Add-Type -TypeDefinition @'
    namespace PowerShellUtils
    {
        using System;
        using System.Runtime.InteropServices;

        public sealed class PinnedArray<T> : IDisposable
        {
            private readonly T[] array;
            private readonly GCHandle gcHandle;
            public readonly bool ClearOnDispose = true;

            private bool isDisposed = false;

            public static implicit operator T[](PinnedArray<T> pinnedArray)
            {
                return pinnedArray.Array;
            }

            public T this[int key]
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array[key];
                }

                set
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    array[key] = value;
                }
            }

            public T[] Array
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array;
                }
            }

            public int Length
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array.Length;
                }
            }

            public int Count
            {
                get { return Length; }
            }

            public PinnedArray(uint count)
            {
                array = new T[count];
                gcHandle = GCHandle.Alloc(Array, GCHandleType.Pinned);
            }

            public PinnedArray(uint count, bool clearOnDispose) : this(count)
            {
                ClearOnDispose = clearOnDispose;
            }

            public PinnedArray(T[] array)
            {
                if (array == null) { throw new ArgumentNullException("array"); }

                this.array = array;
                gcHandle = GCHandle.Alloc(this.array, GCHandleType.Pinned);
            }

            public PinnedArray(T[] array, bool clearOnDispose) : this(array)
            {
                ClearOnDispose = clearOnDispose;
            }

            ~PinnedArray()
            {
                Dispose();
            }

            public void Dispose()
            {
                if (isDisposed) { return; }

                if (array != null && ClearOnDispose) { System.Array.Clear(array, 0, array.Length); }
                if (gcHandle != null) { gcHandle.Free(); }

                isDisposed = true;
            }
        }
    }
'@

# SIG # Begin signature block
# MIIQ8AYJKoZIhvcNAQcCoIIQ4TCCEN0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC03a4LkMvR1a4/
# 9vnDJNMengMkB7EzAQBrlVbBscGU+aCCDg0wggO3MIICn6ADAgECAhAM5+DlF9hG
# /o/lYPwb8DA5MA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0wNjExMTAwMDAwMDBa
# Fw0zMTExMTAwMDAwMDBaMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lD
# ZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAK0OFc7kQ4BcsYfzt2D5cRKlrtwmlIiq9M71IDkoWGAM+IDaqRWVMmE8
# tbEohIqK3J8KDIMXeo+QrIrneVNcMYQq9g+YMjZ2zN7dPKii72r7IfJSYd+fINcf
# 4rHZ/hhk0hJbX/lYGDW8R82hNvlrf9SwOD7BG8OMM9nYLxj+KA+zp4PWw25EwGE1
# lhb+WZyLdm3X8aJLDSv/C3LanmDQjpA1xnhVhyChz+VtCshJfDGYM2wi6YfQMlqi
# uhOCEe05F52ZOnKh5vqk2dUXMXWuhX0irj8BRob2KHnIsdrkVxfEfhwOsLSSplaz
# vbKX7aqn8LfFqD+VFtD/oZbrCF8Yd08CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEXroq/0ksuCMS1Ri6enIZ3zbcgP
# MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUA
# A4IBAQCiDrzf4u3w43JzemSUv/dyZtgy5EJ1Yq6H6/LV2d5Ws5/MzhQouQ2XYFwS
# TFjk0z2DSUVYlzVpGqhH6lbGeasS2GeBhN9/CTyU5rgmLCC9PbMoifdf/yLil4Qf
# 6WXvh+DfwWdJs13rsgkq6ybteL59PyvztyY1bV+JAbZJW58BBZurPSXBzLZ/wvFv
# hsb6ZGjrgS2U60K3+owe3WLxvlBnt2y98/Efaww2BxZ/N3ypW2168RJGYIPXJwS+
# S86XvsNnKmgR34DnDDNmvxMNFG7zfx9jEB76jRslbWyPpbdhAbHSoyahEHGdreLD
# +cOZUbcrBwjOLuZQsqf6CkUvovDyMIIFGjCCBAKgAwIBAgIQBGmOyDBQUQKKmQd8
# G6DyrjANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhE
# aWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTE1MDQw
# MTAwMDAwMFoXDTE2MDYxNjEyMDAwMFowYTELMAkGA1UEBhMCQ0ExCzAJBgNVBAgT
# Ak9OMREwDwYDVQQHEwhCcmFtcHRvbjEYMBYGA1UEChMPRGF2aWQgTGVlIFd5YXR0
# MRgwFgYDVQQDEw9EYXZpZCBMZWUgV3lhdHQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDEkWriT9tO2ZMDtjX9tCPoUBGkwuhUyLt45ab9WTX5OyO5Ym7j
# +SMay+NSrfpkuudQKRPdu2SAimNNTFiNShrqHeLs5mdWAlA9DcKfcT/5ZIfGcwUH
# Bd7iajpBdPrwi178PfTjX9dcCmECkksnXii1+gL4j0WG38bMHS5QnICthSzczV/i
# Io/WRx9bDv7nYUMcHL83HYGLyHiaU9ia1vN0lLRqvM/1YMrDyipw6drgDJHmp0SN
# mNq+4qXTZsvF2buVpCn77av17j038MM9/maCbz8KpxT6VoFdp+1NugeT+80I054X
# AG0m1D1iDho7GQRSDsvzsk0z1SMOOgc5zk7tAgMBAAGjggG7MIIBtzAfBgNVHSME
# GDAWgBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQUPup9rwK/lMYoH5Qb
# 0iHlV/trvxQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcG
# A1UdHwRwMG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtY3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
# c2hhMi1hc3N1cmVkLWNzLWcxLmNybDBCBgNVHSAEOzA5MDcGCWCGSAGG/WwDATAq
# MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGEBggr
# BgEFBQcBAQR4MHYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBOBggrBgEFBQcwAoZCaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0U0hBMkFzc3VyZWRJRENvZGVTaWduaW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAw
# DQYJKoZIhvcNAQELBQADggEBAN8+txwY2kneaLV1H/dOX4z/61sdAo/2r5EgI8LA
# xILnfOpsWg5zVuQQaLonOus+S/Mz5+QXpj2Y4gJ456jDj83Lm2fRWUBLDPRgJJV0
# eLbKcpmuvP/AZMHcyemDQXH9uiptROIB4Tbn72jW6brLq2cfJP3kGnRl9f/CdXCS
# VJnTV+CJ3KpkeudaQWDXeIbxN3Kl+CTVk7Kwt9WV6mdJjUsXTG8GinXLoUOU1TWK
# ujD34R3QWB6Hj0THRStZXIJiEllFxgi+pgfxlZs1zqAtjwF7HgqUEmUOYaYFrZou
# DTJkbf6LuBnRqZprXuj4F04BxEcH5kOcYZJImmX4BdMiFcowggUwMIIEGKADAgEC
# AhAECRgbX9W7ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMzEw
# MjIxMjAwMDBaFw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNV
# BAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4Rr2d3B9MLMUkZz9D7
# RZmxOttE9X/lqJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrwnIal2CWsDnkoOn7p
# 0WfTxvspJ8fTeyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnCwlLyFGeKiUXULaGj
# 6YgsIJWuHEqHCN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8y5Kh5TsxHM/q8grk
# V7tKtel05iv+bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM0SAlI+sIZD5SlsHy
# DxL0xY4PwaLoLFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6fpjOp/RnfJZPRAgMB
# AAGjggHNMIIByTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
# gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBPBgNVHSAESDBGMDgG
# CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzAKBghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoKo6XqcQPAYPkt9mV1
# DlgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDQYJKoZIhvcNAQEL
# BQADggEBAD7sDVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+C2D9wz0PxK+L/e8q
# 3yBVN7Dh9tGSdQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119EefM2FAaK95xGTlz/
# kLEbBw6RFfu6r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR4pwUR6F6aGivm6dc
# IFzZcbEMj7uo+MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4vcn4c10lFluhZHen6
# dGRrsutmQ9qzsIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwHgfqL2vmCSfdibqFT
# +hKUGIUukpHqaGxEMrJmoecYpJpkUe8xggI5MIICNQIBATCBhjByMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBT
# aWduaW5nIENBAhAEaY7IMFBRAoqZB3wboPKuMA0GCWCGSAFlAwQCAQUAoIGEMBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IN4kAlMqpMFeQdFT32ZSMcckLvoLKOIJ55tmD22A3LE+MA0GCSqGSIb3DQEBAQUA
# BIIBAI8OfD0BwEV6AtaurBEOVe6guecRuOsnLli5PcmhomPeVhRUh+xaeHqrrYSp
# iVvihhOOCCC+yTXdNOoDnzlc3oSyFZA16NPzH000JCgBzZmkll2xa5mRCYuM20W9
# auIEdDq8GbItDOibhLVSLtdFxw+CcQUHHVD1MAow3bmyLe2gfJzTPexn57rnuJm/
# RhBPcamQx+IM7hDJqWQNZx6XwOS5Xkt/5bppg3hhXJSckg6Iqj7Tq3h1ZpY0oKK9
# +muD5J8/pzmB6vdCOyjL9cGJDda8z6AOnoOPVnawtlOxkJaXlVacDaKGthFPe6RR
# mcMlOE6q5/KUY8KCgSr7bRTBSLU=
# SIG # End signature block
