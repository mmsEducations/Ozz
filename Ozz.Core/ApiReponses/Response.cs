namespace Ozz.Core.ApiReponses
{
    public class Response<T>
    {
        public int StatusCode { get; set; } //İşlem status codu
        public bool IsSuccess { get; set; } //İşlem durumunu 
        public string Message { get; set; } //mesaj verme ve hata için kullanılır
        public string Error { get; set; } //Hata mesajlarnını tutar 
        public T Data { get; set; }
    }
}
