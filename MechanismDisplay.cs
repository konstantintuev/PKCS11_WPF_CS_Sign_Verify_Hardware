namespace ModernSign
{
    public class MechanismDisplay
    {
        // Holds the underlying mechanism value as ulong (you can also store it as CKM if you prefer)
        public ulong MechanismValue { get; set; }
        
        // DisplayName is what will be shown in the ComboBox.
        public string DisplayName { get; set; }
    }
}