export const getLocalISODate = (date: Date = new Date()): string => {
    const pad = (n: number, length: number = 2) => n.toString().padStart(length, '0');

    const y = date.getFullYear();
    const m = pad(date.getMonth() + 1);
    const d = pad(date.getDate());
    const h = pad(date.getHours());
    const min = pad(date.getMinutes());
    const s = pad(date.getSeconds());
    const ms = pad(date.getMilliseconds(), 3); // milliseconds are 3 digits

    const tzOffset = -date.getTimezoneOffset();
    const sign = tzOffset >= 0 ? '+' : '-';
    const tzH = pad(Math.floor(Math.abs(tzOffset) / 60));
    const tzM = pad(Math.abs(tzOffset) % 60);

    return `${y}-${m}-${d}T${h}:${min}:${s}.${ms}${sign}${tzH}:${tzM}`;
};

export const getFriendlyDate = (date: Date = new Date()): string => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');

  return `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;
}
