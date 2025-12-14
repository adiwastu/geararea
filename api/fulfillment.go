package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// --- Komerce Payload Structs ---

type KomerceStoreRequest struct {
	OrderDate             string               `json:"order_date"`
	BrandName             string               `json:"brand_name"`
	ShipperName           string               `json:"shipper_name"`
	ShipperPhone          string               `json:"shipper_phone"`
	ShipperDestinationID  int                  `json:"shipper_destination_id"`
	ShipperAddress        string               `json:"shipper_address"`
	ShipperEmail          string               `json:"shipper_email"`
	ReceiverName          string               `json:"receiver_name"`
	ReceiverPhone         string               `json:"receiver_phone"`
	ReceiverDestinationID int                  `json:"receiver_destination_id"`
	ReceiverAddress       string               `json:"receiver_address"`
	Shipping              string               `json:"shipping"`       // e.g. JNE
	ShippingType          string               `json:"shipping_type"`  // e.g. REG
	PaymentMethod         string               `json:"payment_method"` // BANK TRANSFER
	ShippingCost          int                  `json:"shipping_cost"`
	ShippingCashback      int                  `json:"shipping_cashback"`
	ServiceFee            int                  `json:"service_fee"`
	AdditionalCost        int                  `json:"additional_cost"`
	GrandTotal            int                  `json:"grand_total"`
	CodValue              int                  `json:"cod_value"`
	InsuranceValue        float64              `json:"insurance_value"`
	OrderDetails          []KomerceOrderDetail `json:"order_details"`
}

type KomerceOrderDetail struct {
	ProductName        string `json:"product_name"`
	ProductVariantName string `json:"product_variant_name"`
	ProductPrice       int    `json:"product_price"`
	ProductWeight      int    `json:"product_weight"`
	ProductWidth       int    `json:"product_width"`
	ProductHeight      int    `json:"product_height"`
	ProductLength      int    `json:"product_length"`
	Qty                int    `json:"qty"`
	Subtotal           int    `json:"subtotal"`
}

type KomerceResponse struct {
	Meta struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"meta"`
	Data struct {
		OrderID int    `json:"order_id"`
		OrderNo string `json:"order_no"` // The KOM... ID
	} `json:"data"`
}

// --- The Mock Payment Handler ---

func mockPayHandler(w http.ResponseWriter, r *http.Request) {
	// 0. Check Environment Variable
	apiKey := os.Getenv("KOMERCE_API_KEY")
	if apiKey == "" {
		fmt.Println("CRITICAL: KOMERCE_API_KEY is missing from environment")
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	// 1. Parse Order ID
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 { // /orders/{id}/pay
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	orderIDStr := parts[len(parts)-2] // "pay" is last, ID is 2nd to last
	orderID, _ := strconv.Atoi(orderIDStr)

	ctx := r.Context()

	// 2. FETCH DATA (Buyer, Seller, Order, Logistics)
	// We use COALESCE on phones/emails to ensure we don't send NULL to Komerce
	var kReq KomerceStoreRequest
	var sellerID int

	err := db.QueryRow(ctx, `
		SELECT 
			-- Order Basics
			o.seller_id, o.shipping_provider, o.shipping_service, o.shipping_cost, o.grand_total,
			-- Seller (Shipper)
			s.full_name, COALESCE(s.phone, '08123456789'), s.location_id, s.address, s.email,
			-- Buyer (Receiver)
			b.full_name, COALESCE(b.phone, '08123456789'), o.destination_location_id, o.shipping_address
		FROM orders o
		JOIN users s ON o.seller_id = s.id
		JOIN users b ON o.buyer_id = b.id
		WHERE o.id = $1 AND o.status = 'PENDING_PAYMENT'
	`, orderID).Scan(
		&sellerID, &kReq.Shipping, &kReq.ShippingType, &kReq.ShippingCost, &kReq.GrandTotal,
		&kReq.ShipperName, &kReq.ShipperPhone, &kReq.ShipperDestinationID, &kReq.ShipperAddress, &kReq.ShipperEmail,
		&kReq.ReceiverName, &kReq.ReceiverPhone, &kReq.ReceiverDestinationID, &kReq.ReceiverAddress,
	)

	if err != nil {
		fmt.Printf("MockPay DB Error: %v\n", err)
		http.Error(w, "order not found or already paid", http.StatusNotFound)
		return
	}

	// 3. FETCH PRODUCTS (Order Items)
	rows, err := db.Query(ctx, `
		SELECT p.title, p.price, p.weight_grams, p.length_cm, p.width_cm, p.height_cm
		FROM order_items oi
		JOIN products p ON oi.product_id = p.id
		WHERE oi.order_id = $1
	`, orderID)
	if err != nil {
		http.Error(w, "db error items", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p KomerceOrderDetail
		var l, wi, h *int // Handle nullable dims
		if err := rows.Scan(&p.ProductName, &p.ProductPrice, &p.ProductWeight, &l, &wi, &h); err != nil {
			continue
		}
		// Defaults
		p.ProductVariantName = "-"
		p.Qty = 1
		p.Subtotal = p.ProductPrice
		if l != nil {
			p.ProductLength = *l
		} else {
			p.ProductLength = 10
		}
		if wi != nil {
			p.ProductWidth = *wi
		} else {
			p.ProductWidth = 10
		}
		if h != nil {
			p.ProductHeight = *h
		} else {
			p.ProductHeight = 10
		}

		kReq.OrderDetails = append(kReq.OrderDetails, p)
	}

	// 4. Fill Remaining Constants
	jakartaTime := time.Now().UTC().Add(7 * time.Hour)
	kReq.OrderDate = jakartaTime.Format("2006-01-02 15:04:05")
	kReq.BrandName = "GearArea"
	kReq.PaymentMethod = "BANK TRANSFER"
	kReq.CodValue = 0 // Since it's bank transfer
	kReq.ServiceFee = 0
	kReq.AdditionalCost = 0
	kReq.InsuranceValue = 0

	// 5. SEND TO KOMERCE
	komercePayload, _ := json.Marshal(kReq)

	client := &http.Client{Timeout: 10 * time.Second}
	reqAPI, _ := http.NewRequest("POST", "https://api-sandbox.collaborator.komerce.id/order/api/v1/orders/store", bytes.NewBuffer(komercePayload))
	reqAPI.Header.Set("Content-Type", "application/json")
	reqAPI.Header.Set("x-api-key", apiKey) // Uses the ENV variable

	resp, err := client.Do(reqAPI)
	if err != nil {
		fmt.Printf("Komerce Network Error: %v\n", err)
		http.Error(w, "komerce connection failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var kResp KomerceResponse
	json.Unmarshal(bodyBytes, &kResp)

	// 6. HANDLE SUCCESS OR FAILURE
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		fmt.Printf("Komerce API Error [%d]: %s\n", resp.StatusCode, string(bodyBytes))
		// Return 400 so the client knows it failed logic, not just server error
		http.Error(w, fmt.Sprintf("Shipping Partner Error: %s", kResp.Meta.Message), http.StatusBadRequest)
		return
	}

	if kResp.Data.OrderNo == "" {
		fmt.Println("Komerce Success but empty OrderNo")
		http.Error(w, "shipping partner returned no ID", http.StatusBadGateway)
		return
	}

	// 7. SUCCESS: Update Database
	_, err = db.Exec(ctx, `
		UPDATE orders 
		SET status = 'PAID', 
		    paid_at = NOW(), 
		    external_order_id = $1 
		WHERE id = $2`,
		kResp.Data.OrderNo, orderID)

	if err != nil {
		fmt.Printf("DB Update Error: %v\n", err)
		http.Error(w, "failed to update local db", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "paid",
		"komerce_id": kResp.Data.OrderNo,
	})
}
